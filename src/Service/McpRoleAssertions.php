<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Site\Settings;
use Drupal\user\RoleInterface;

/**
 * Asserts that governed roles hold no permission that walks around the policy.
 *
 * A policy profile constrains what an agent may do *through the MCP channel*.
 * It says nothing about what the governed Drupal role may do outside it, and
 * the two are not the same boundary: a role holding `bypass file gate` reaches
 * gated private files straight off `/system/files/…`, with no MCP request and
 * therefore no policy, no redaction and no audit row. The module could not see
 * that, so the profile's guarantees quietly stopped being true.
 *
 * This service closes the gap by reading the permissions actually held by every
 * governed role and reporting the ones a profile declares must never be held.
 *
 * Two subtleties decide whether the check is worth anything:
 *
 *  - **Effective, not listed, permissions.** An account's permissions are the
 *    union of all its roles, and every governed account is authenticated. A
 *    bypass granted to `authenticated` is therefore held by every governed
 *    role while appearing in none of their permission arrays — the check would
 *    read clean while the site was wide open.
 *  - **`is_admin` roles hold everything implicitly.** Their permission array is
 *    empty by design; enumerating it proves nothing. An `is_admin` governed
 *    role is reported as its own violation class rather than scanned.
 */
final class McpRoleAssertions {

  /**
   * A governed role that holds a permission its profile forbids.
   */
  public const VIOLATION_FORBIDDEN = 'forbidden_permission';

  /**
   * A governed role flagged is_admin, and therefore holding every permission.
   */
  public const VIOLATION_IS_ADMIN = 'is_admin';

  /**
   * Constructs an McpRoleAssertions service.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (loads user_role entities).
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   The policy resolver — supplies the governed role set and the profile
   *   covering each role, so this check uses exactly the same notion of
   *   "governed" as enforcement does.
   * @param \Drupal\Core\Site\Settings $settings
   *   Site settings. The environment name for scoped acknowledgements is read
   *   from here (`mcp_sentinel.environment`), never from config — exported
   *   config travels between environments, and an environment recorded in
   *   config is how prod would come to believe it is dev.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly McpPolicyResolver $policyResolver,
    private readonly Settings $settings,
  ) {}

  /**
   * Returns every escape-hatch violation across all governed roles.
   *
   * @return array<int, array{role: string, permission: string, type: string, profile: string, via: string}>
   *   One entry per violation. 'via' is 'direct' when the governed role itself
   *   carries the permission and 'authenticated' when it inherits it, because
   *   the fix differs: revoke it from the agent role, or from every logged-in
   *   user on the site.
   */
  public function violations(): array {
    $authenticated = $this->loadRole(RoleInterface::AUTHENTICATED_ID);
    $inherited = $authenticated?->getPermissions() ?? [];
    $inheritedAdmin = $authenticated?->isAdmin() === TRUE;

    $violations = [];
    foreach ($this->policyResolver->getGovernedRoles() as $roleId) {
      $role = $this->loadRole($roleId);
      if ($role === NULL) {
        // A governed role that does not exist grants nothing, so it is not a
        // bypass. It is still a broken reference; the "not governing any
        // request" requirement already covers configuration that cannot bite.
        continue;
      }
      $violations = array_merge($violations, $this->evaluate(
        $roleId,
        $role->getPermissions(),
        $role->isAdmin(),
        $inherited,
        $inheritedAdmin,
      ));
    }

    return $violations;
  }

  /**
   * Evaluates a role from config data rather than from a loaded entity.
   *
   * Needed by the ConfigEvents::SAVE listener. That event fires while the role
   * is still being saved: the config storage already holds the new data, but
   * the entity static cache does not, so re-loading the role there returns the
   * *previous* permissions and the check silently sees nothing. A detector that
   * never fires is worse than no detector, so the save path passes the data it
   * was handed instead of asking for it again.
   *
   * @param string $roleId
   *   The role ID whose configuration was saved.
   * @param array $permissions
   *   The permissions in the saved configuration.
   * @param bool $isAdmin
   *   The is_admin flag in the saved configuration.
   *
   * @return array<int, array{role: string, permission: string, type: string, profile: string, via: string}>
   *   Violations attributable to this save. Saving 'authenticated' is
   *   evaluated against every governed role, because a grant there is held by
   *   all of them.
   */
  public function violationsForSavedRole(string $roleId, array $permissions, bool $isAdmin): array {
    $governed = $this->policyResolver->getGovernedRoles();

    if ($roleId === RoleInterface::AUTHENTICATED_ID) {
      $violations = [];
      foreach ($governed as $governedId) {
        $role = $this->loadRole($governedId);
        if ($role === NULL) {
          continue;
        }
        $violations = array_merge($violations, $this->evaluate(
          $governedId,
          $role->getPermissions(),
          $role->isAdmin(),
          $permissions,
          $isAdmin,
        ));
      }
      return $violations;
    }

    if (!in_array($roleId, $governed, TRUE)) {
      return [];
    }

    $authenticated = $this->loadRole(RoleInterface::AUTHENTICATED_ID);
    return $this->evaluate(
      $roleId,
      $permissions,
      $isAdmin,
      $authenticated?->getPermissions() ?? [],
      $authenticated?->isAdmin() === TRUE,
    );
  }

  /**
   * Evaluates one governed role's effective permissions against its profile.
   *
   * @param string $roleId
   *   The governed role ID.
   * @param string[] $permissions
   *   Permissions held by the role itself.
   * @param bool $isAdmin
   *   Whether the role is flagged is_admin.
   * @param string[] $inherited
   *   Permissions held by the 'authenticated' role.
   * @param bool $inheritedAdmin
   *   Whether 'authenticated' is flagged is_admin.
   *
   * @return array<int, array{role: string, permission: string, type: string, profile: string, via: string}>
   *   Violations for this role.
   */
  private function evaluate(
    string $roleId,
    array $permissions,
    bool $isAdmin,
    array $inherited,
    bool $inheritedAdmin,
  ): array {
    $profile = $this->policyResolver->resolveForRoles([$roleId]);
    if ($profile === NULL) {
      return [];
    }

    // An is_admin role holds every permission implicitly — including any a
    // module installed tomorrow will define — so there is nothing to
    // enumerate. The governed role inherits that from 'authenticated' too: if
    // every logged-in user is an admin, so is the agent.
    if ($isAdmin || $inheritedAdmin) {
      return [
        [
          'role' => $roleId,
          'permission' => '*',
          'type' => self::VIOLATION_IS_ADMIN,
          'profile' => $profile->id(),
          'via' => $isAdmin ? 'direct' : 'authenticated',
        ],
      ];
    }

    $forbidden = $profile->getForbiddenRolePermissions();
    if ($forbidden === []) {
      return [];
    }
    $acknowledged = $profile->getAcknowledgedRolePermissions();

    $violations = [];
    foreach ($forbidden as $permission) {
      $heldDirectly = in_array($permission, $permissions, TRUE);
      $heldByAll = in_array($permission, $inherited, TRUE);
      if (!$heldDirectly && !$heldByAll) {
        continue;
      }
      if ($this->isAcknowledged($roleId, $permission, $acknowledged)) {
        // A deliberate grant, recorded in exported configuration. It stops
        // being a finding and becomes a decision somebody signed.
        continue;
      }
      $violations[] = [
        'role' => $roleId,
        'permission' => $permission,
        'type' => self::VIOLATION_FORBIDDEN,
        'profile' => $profile->id(),
        'via' => $heldDirectly ? 'direct' : 'authenticated',
      ];
    }

    return $violations;
  }

  /**
   * Whether a role/permission pair is acknowledged on this environment.
   *
   * Grammar:
   *  - `role_id:permission` — applies on every environment.
   *  - `role_id:permission@environment` — applies only when
   *    `$settings['mcp_sentinel.environment']` equals `environment`.
   *
   * Fails closed: with no environment declared in settings.php, a scoped
   * acknowledgement does not apply and the violation is reported. A site that
   * forgets to set it gets the strict answer, never the permissive one.
   *
   * VIOLATION_IS_ADMIN is never acknowledged — that path returns before this
   * method is called. An is_admin role cannot be signed into compliance.
   *
   * @param string $roleId
   *   The governed role ID.
   * @param string $permission
   *   The permission machine name.
   * @param string[] $acknowledged
   *   Entries from the profile's acknowledged_role_permissions.
   *
   * @return bool
   *   TRUE when the pair is acknowledged for this environment.
   */
  private function isAcknowledged(string $roleId, string $permission, array $acknowledged): bool {
    $unscoped = $roleId . ':' . $permission;
    if (in_array($unscoped, $acknowledged, TRUE)) {
      return TRUE;
    }

    // settings.php only — never config. Exported config travels dev → prod.
    $environment = (string) ($this->settings->get('mcp_sentinel.environment') ?? '');
    if ($environment === '') {
      // Fail closed: scoped entries need an environment to match against.
      return FALSE;
    }

    return in_array($unscoped . '@' . $environment, $acknowledged, TRUE);
  }

  /**
   * Renders a violation as an operator-facing sentence.
   *
   * @param array{role: string, permission: string, type: string, profile: string, via: string} $violation
   *   A violation from violations().
   *
   * @return string
   *   A message naming the role, the permission and the remedy.
   */
  public function describe(array $violation): string {
    if ($violation['type'] === self::VIOLATION_IS_ADMIN) {
      return $violation['via'] === 'authenticated'
        ? sprintf(
          "Governed role '%s' effectively holds every permission on the site because the 'authenticated' role is flagged as an admin role. Policy profile '%s' cannot constrain it, and neither can anything else. Remove is_admin from 'authenticated'.",
          $violation['role'],
          $violation['profile'],
        )
        : sprintf(
          "Governed role '%s' is an admin role, so it holds every permission on the site — including any that bypass MCP Sentinel. Policy profile '%s' cannot constrain it. Govern a purpose-built role instead.",
          $violation['role'],
          $violation['profile'],
        );
    }

    if ($violation['via'] === 'authenticated') {
      return sprintf(
        "Governed role '%s' effectively holds '%s' because the 'authenticated' role grants it to every logged-in user. Policy profile '%s' forbids it. Revoke it from 'authenticated', or acknowledge it explicitly on the profile.",
        $violation['role'],
        $violation['permission'],
        $violation['profile'],
      );
    }

    return sprintf(
      "Governed role '%s' holds '%s', which policy profile '%s' forbids: it can be used outside the MCP channel, where no policy, redaction or audit applies. Revoke it, or acknowledge it explicitly on the profile.",
      $violation['role'],
      $violation['permission'],
      $violation['profile'],
    );
  }

  /**
   * Returns whether a role ID refers to an is_admin role.
   *
   * Used by the configuration forms to refuse governing such a role in the
   * first place, rather than only reporting it afterwards.
   *
   * @param string $roleId
   *   The role ID.
   *
   * @return bool
   *   TRUE when the role exists and is flagged is_admin.
   */
  public function isAdminRole(string $roleId): bool {
    return $this->loadRole($roleId)?->isAdmin() === TRUE;
  }

  /**
   * Loads a role entity by ID.
   *
   * @param string $roleId
   *   The role ID.
   *
   * @return \Drupal\user\RoleInterface|null
   *   The role, or NULL when it does not exist or storage is unavailable.
   */
  private function loadRole(string $roleId): ?RoleInterface {
    try {
      $role = $this->entityTypeManager->getStorage('user_role')->load($roleId);
    }
    catch (\Throwable) {
      return NULL;
    }
    return $role instanceof RoleInterface ? $role : NULL;
  }

}
