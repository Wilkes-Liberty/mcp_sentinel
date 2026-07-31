<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel_approval\Entity\McpAdminGrantInterface;
use Drupal\user\RoleInterface;
use Drupal\user\UserInterface;

/**
 * Grants and reaps the time-boxed mcp_admin break-glass role.
 *
 * The mcp_admin role is never standing. A grant is recorded as an
 * mcp_admin_grant entity with an expiry derived from break_glass_ttl_seconds;
 * a cron reaper (mcp_sentinel_approval_cron) calls reapExpired() to remove the
 * role and mark the grant revoked once the expiry passes. This mirrors the
 * content-lock reaper: cron-based revocation survives missed runs, where a
 * delayed queue item could be lost.
 *
 * Enterprise posture (least privilege + separation of duties):
 * - The shipped role is non-is_admin with an enumerated permission set
 *   (config/optional/user.role.mcp_admin.yml). It is not superuser.
 * - Grant refuses when the role is missing or still flagged is_admin.
 * - "approve mcp sentinel operations" is deliberately not on this role so a
 *   break-glass session cannot rubber-stamp the next elevation.
 * - Agent capability changes stay on the policy profile, not this role.
 */
final class McpBreakGlassManager {

  /**
   * The break-glass admin role id.
   */
  public const string ROLE_ID = 'mcp_admin';

  /**
   * Default grant lifetime (seconds) when none is configured.
   */
  private const DEFAULT_TTL = 3600;

  /**
   * The stored 'revoked' value for a live grant, as an int rather than FALSE.
   *
   * An entity query passes its condition value to the database layer unchanged,
   * and only the pgsql driver casts booleans (Connection::query(), working
   * around https://bugs.php.net/bug.php?id=48383). SQLite does not: a PHP FALSE
   * binds as PARAM_STR, becomes '', and `revoked = ''` matches no row whose
   * stored value is 0. MySQL hides it by coercing '' to 0.
   *
   * So `->condition('revoked', FALSE)` made this reaper a silent no-op on every
   * SQLite site — expired grants were never revoked and nothing errored, which
   * is the worst way for a break-glass expiry to fail. Bind the stored integer.
   */
  private const NOT_REVOKED = 0;

  /**
   * Constructs an McpBreakGlassManager.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (reads break_glass_ttl_seconds).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The base audit logger.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly TimeInterface $time,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * Grants the break-glass role to a user for the configured TTL.
   *
   * Fail-closed: refuses when the grantee is missing, when the mcp_admin role
   * is missing, or when that role is still is_admin. Those are not soft
   * warnings — a time-boxed grant that silently means every permission is not
   * a control.
   *
   * @param int $uid
   *   The grantee user id.
   *
   * @return array{granted: bool, message: string, expires: int}
   *   'granted' is TRUE when the role was added and a grant recorded.
   *   'expires' is a Unix timestamp when granted; 0 when refused.
   */
  public function grant(int $uid): array {
    $user = $this->entityTypeManager->getStorage('user')->load($uid);
    // Entity storage returns EntityInterface|null; narrow before User API use.
    if (!$user instanceof UserInterface) {
      return [
        'granted' => FALSE,
        'message' => sprintf('User %d not found.', $uid),
        'expires' => 0,
      ];
    }

    $role = $this->entityTypeManager->getStorage('user_role')->load(self::ROLE_ID);
    // Role must exist as config (optional install or site-created). We never
    // invent a standing superuser role at grant time.
    if (!$role instanceof RoleInterface) {
      return [
        'granted' => FALSE,
        'message' => sprintf('The %s role does not exist on this site.', self::ROLE_ID),
        'expires' => 0,
      ];
    }

    // is_admin holds every permission implicitly. Granting that as "break-
    // glass" would be silent superuser elevation. The shipped role is
    // enumerated and non-admin; refuse until the site fixes the role.
    if ($role->isAdmin()) {
      return [
        'granted' => FALSE,
        'message' => sprintf(
          'Refusing to grant %s: the role is flagged is_admin, so it holds every permission on the site. Clear is_admin and use the enumerated break-glass permission set (see mcp_sentinel_approval config/optional).',
          self::ROLE_ID,
        ),
        'expires' => 0,
      ];
    }

    $now = $this->time->getRequestTime();
    $expires = $now + $this->ttl();

    // Overlapping grants (renew before first expiry) re-use the role on the
    // account; each grant row still has its own expiry for the reaper.
    if (!$user->hasRole(self::ROLE_ID)) {
      $user->addRole(self::ROLE_ID);
      $user->save();
    }

    $grant = $this->entityTypeManager->getStorage('mcp_admin_grant')->create([
      'uid' => $uid,
      'granted' => $now,
      'expires' => $expires,
      // FALSE here; entity queries bind NOT_REVOKED (0). See constant.
      'revoked' => FALSE,
    ]);
    $grant->save();

    $this->auditLogger->log('mcp_admin_granted', [
      'entity_type' => 'user',
      'id' => (string) $uid,
      'expires' => $expires,
      'grant_id' => (int) $grant->id(),
    ]);

    return [
      'granted' => TRUE,
      'message' => sprintf('Granted %s to user %d until %d.', self::ROLE_ID, $uid, $expires),
      'expires' => $expires,
    ];
  }

  /**
   * Revokes all expired, not-yet-revoked grants. Intended for cron.
   *
   * @return int
   *   The number of grants revoked.
   */
  public function reapExpired(): int {
    $storage = $this->entityTypeManager->getStorage('mcp_admin_grant');
    $now = $this->time->getRequestTime();
    $ids = $storage->getQuery()
      ->accessCheck(FALSE)
      // 0, not FALSE: see self::NOT_REVOKED.
      ->condition('revoked', self::NOT_REVOKED)
      ->condition('expires', $now, '<=')
      ->execute();
    if (!$ids) {
      return 0;
    }

    $userStorage = $this->entityTypeManager->getStorage('user');
    $revoked = 0;
    foreach ($storage->loadMultiple($ids) as $grant) {
      if (!$grant instanceof McpAdminGrantInterface) {
        continue;
      }
      $uid = $grant->getUserId();
      $user = $userStorage->load($uid);
      // Only remove the role if no other still-active grant covers this user.
      if ($user !== NULL && $user->hasRole(self::ROLE_ID) && !$this->hasOtherActiveGrant($uid, (int) $grant->id())) {
        $user->removeRole(self::ROLE_ID);
        $user->save();
      }
      $grant->setRevoked(TRUE)->save();
      $this->auditLogger->log('mcp_admin_revoked', [
        'entity_type' => 'user',
        'id' => (string) $uid,
        'grant_id' => (int) $grant->id(),
      ]);
      $revoked++;
    }

    return $revoked;
  }

  /**
   * Returns TRUE when the user has another active (non-expired) grant.
   *
   * @param int $uid
   *   The grantee user id.
   * @param int $excludeGrantId
   *   The grant id to exclude (the one being reaped).
   *
   * @return bool
   *   TRUE when a still-active grant remains.
   */
  private function hasOtherActiveGrant(int $uid, int $excludeGrantId): bool {
    $storage = $this->entityTypeManager->getStorage('mcp_admin_grant');
    $now = $this->time->getRequestTime();
    $ids = $storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('uid', $uid)
      // 0, not FALSE: see self::NOT_REVOKED.
      ->condition('revoked', self::NOT_REVOKED)
      ->condition('expires', $now, '>')
      ->condition('id', $excludeGrantId, '<>')
      ->range(0, 1)
      ->execute();
    return $ids !== [];
  }

  /**
   * Returns the configured grant TTL in seconds.
   *
   * @return int
   *   The TTL; falls back to DEFAULT_TTL when unset or non-positive.
   */
  private function ttl(): int {
    $ttl = (int) $this->configFactory
      ->get('mcp_sentinel_approval.settings')
      ->get('break_glass_ttl_seconds');
    return $ttl > 0 ? $ttl : self::DEFAULT_TTL;
  }

}
