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
 *   (ALLOWED_PERMISSIONS; config/optional/user.role.mcp_admin.yml). Not
 *   superuser.
 * - Grant refuses when the role is missing, is_admin, or holds any permission
 *   outside ALLOWED_PERMISSIONS (the allowlist is an elevation invariant).
 * - A narrower subset of the allowlist still grants (safer); status report
 *   WARNINGs incomplete operator shells.
 * - "approve mcp sentinel operations" is outside the allowlist so break-glass
 *   cannot rubber-stamp the next elevation.
 * - Agent capability changes stay on the policy profile, not this role.
 */
final class McpBreakGlassManager {

  /**
   * The break-glass admin role id.
   */
  public const string ROLE_ID = 'mcp_admin';

  /**
   * Permissions the break-glass role may hold (least-privilege ceiling).
   *
   * Single source of truth for grant-time refuse, status-report drift, tests,
   * and the optional config YAML. Keep this list identical to
   * config/optional/user.role.mcp_admin.yml. Order is not significant; callers
   * that compare sets should sort.
   *
   * Intentionally excluded (non-exhaustive): approve mcp sentinel operations
   * (separation of duties); escape-hatch perms; administer site configuration;
   * administer modules.
   */
  public const array ALLOWED_PERMISSIONS = [
    'access administration pages',
    'view the administration theme',
    'access site reports',
    'view mcp sentinel audit log',
    'administer mcp sentinel',
  ];

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
   * Permissions on the role that sit outside ALLOWED_PERMISSIONS.
   *
   * @param \Drupal\user\RoleInterface $role
   *   The mcp_admin role (or any role checked against the allowlist).
   *
   * @return list<string>
   *   Sorted machine names of disallowed permissions held by the role.
   */
  public static function permissionExtras(RoleInterface $role): array {
    $extras = array_values(array_diff($role->getPermissions(), self::ALLOWED_PERMISSIONS));
    sort($extras);
    return $extras;
  }

  /**
   * Shipped allowlist permissions the role does not hold.
   *
   * A non-empty result is safer than extras (narrower elevation) but means the
   * documented operator shell is incomplete — status report WARNING, not grant
   * refuse.
   *
   * @param \Drupal\user\RoleInterface $role
   *   The mcp_admin role.
   *
   * @return list<string>
   *   Sorted machine names from ALLOWED_PERMISSIONS missing on the role.
   */
  public static function permissionMissing(RoleInterface $role): array {
    $missing = array_values(array_diff(self::ALLOWED_PERMISSIONS, $role->getPermissions()));
    sort($missing);
    return $missing;
  }

  /**
   * Grants the break-glass role to a user for the configured TTL.
   *
   * Fail-closed: refuses when the grantee is missing; when the mcp_admin role
   * is missing; when that role is still is_admin; or when the role holds any
   * permission outside ALLOWED_PERMISSIONS. Those are not soft warnings — a
   * time-boxed grant that silently means more than the allowlist is not a
   * control.
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

    // Allowlist is the elevation ceiling. Extras (including approve-ops) mean
    // the role outgrew least privilege; refuse rather than attach a widened
    // break-glass session. A proper subset still grants.
    $extras = self::permissionExtras($role);
    if ($extras !== []) {
      return [
        'granted' => FALSE,
        'message' => sprintf(
          'Refusing to grant %s: the role holds permissions outside the break-glass allowlist (%s). Remove them from the role (or put them on a standing role that is not time-boxed elevation).',
          self::ROLE_ID,
          implode(', ', $extras),
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

    $revoked = 0;
    foreach ($storage->loadMultiple($ids) as $grant) {
      if (!$grant instanceof McpAdminGrantInterface) {
        continue;
      }
      $this->revokeGrant($grant, 'expired');
      $revoked++;
    }

    return $revoked;
  }

  /**
   * Force-revokes active grants when mcp_admin posture is unsafe.
   *
   * Grant-time allowlist and status-report drift close elevation at the next
   * grant. They do not address a live grant: if an operator widens mcp_admin
   * (or flips is_admin) while someone still holds the role until TTL, that
   * session keeps the widened capability. Cron calls this alongside
   * reapExpired().
   *
   * Unsafe = role missing, is_admin, or any permission outside
   * ALLOWED_PERMISSIONS. Narrower-than-allowlist alone is NOT unsafe (status
   * WARNING only) — do not force-revoke for that.
   *
   * @return int
   *   The number of grants revoked for posture.
   */
  public function reapUnsafePosture(): int {
    $role = $this->entityTypeManager->getStorage('user_role')->load(self::ROLE_ID);
    $posture = 'ok';
    if (!$role instanceof RoleInterface) {
      $posture = 'missing';
    }
    elseif ($role->isAdmin()) {
      $posture = 'is_admin';
    }
    elseif (self::permissionExtras($role) !== []) {
      $posture = 'extras';
    }
    if ($posture === 'ok') {
      return 0;
    }

    $storage = $this->entityTypeManager->getStorage('mcp_admin_grant');
    $now = $this->time->getRequestTime();
    $ids = $storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('revoked', self::NOT_REVOKED)
      ->condition('expires', $now, '>')
      ->execute();
    if (!$ids) {
      return 0;
    }

    $revoked = 0;
    foreach ($storage->loadMultiple($ids) as $grant) {
      if (!$grant instanceof McpAdminGrantInterface) {
        continue;
      }
      $this->revokeGrant($grant, 'role_posture_unsafe', ['posture' => $posture]);
      $revoked++;
    }
    return $revoked;
  }

  /**
   * Returns the user's active (non-expired, non-revoked) grant, if any.
   *
   * Used by the break-glass conduct auditor: a cookie-session holder of
   * mcp_admin is only "elevated" when a live grant row exists.
   *
   * @param int $uid
   *   The user id.
   *
   * @return \Drupal\mcp_sentinel_approval\Entity\McpAdminGrantInterface|null
   *   The first active grant, or NULL.
   */
  public function findActiveGrantFor(int $uid): ?McpAdminGrantInterface {
    if ($uid <= 0) {
      return NULL;
    }
    $storage = $this->entityTypeManager->getStorage('mcp_admin_grant');
    $now = $this->time->getRequestTime();
    $ids = $storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('uid', $uid)
      // 0, not FALSE: see self::NOT_REVOKED.
      ->condition('revoked', self::NOT_REVOKED)
      ->condition('expires', $now, '>')
      ->range(0, 1)
      ->execute();
    if (!$ids) {
      return NULL;
    }
    $grant = $storage->load(reset($ids));
    return $grant instanceof McpAdminGrantInterface ? $grant : NULL;
  }

  /**
   * Marks a grant revoked, removes the role when no other grant covers the user.
   *
   * @param \Drupal\mcp_sentinel_approval\Entity\McpAdminGrantInterface $grant
   *   The grant to revoke.
   * @param string $reason
   *   Audit reason: 'expired' or 'role_posture_unsafe'.
   * @param array $extraMeta
   *   Additional audit metadata (e.g. posture detail).
   */
  private function revokeGrant(McpAdminGrantInterface $grant, string $reason, array $extraMeta = []): void {
    $uid = $grant->getUserId();
    $userStorage = $this->entityTypeManager->getStorage('user');
    $user = $userStorage->load($uid);
    // Only remove the role if no other still-active grant covers this user.
    // Narrow to UserInterface before role API (same posture as grant()).
    if ($user instanceof UserInterface && $user->hasRole(self::ROLE_ID) && !$this->hasOtherActiveGrant($uid, (int) $grant->id())) {
      $user->removeRole(self::ROLE_ID);
      $user->save();
    }
    $grant->setRevoked(TRUE)->save();
    $this->auditLogger->log('mcp_admin_revoked', array_merge([
      'entity_type' => 'user',
      'id' => (string) $uid,
      'grant_id' => (int) $grant->id(),
      'reason' => $reason,
    ], $extraMeta));
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
