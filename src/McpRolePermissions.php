<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\user\RoleInterface;

/**
 * Grants role permissions without the Drupal 11.5-deprecated helpers.
 *
 * The user_role_grant_permissions() function is deprecated in Drupal 11.5
 * and removed in 13. The plural RoleInterface::grantPermissions() and
 * Role::loadOverrideFree() arrived in 11.5, so they cannot be the only path
 * on the 10.6 / 11.3 floor.
 * Config-entity storage has had loadOverrideFree() since Drupal 8, and the
 * singular grantPermission() exists across the whole claimed range.
 */
final class McpRolePermissions {

  /**
   * Grants permissions on the override-free role config, then saves it.
   *
   * @param string $rid
   *   The role id.
   * @param string[] $permissions
   *   Permission machine names to grant.
   */
  public static function grant(string $rid, array $permissions): void {
    $storage = \Drupal::entityTypeManager()->getStorage('user_role');
    $role = $storage->loadOverrideFree($rid);
    if (!$role instanceof RoleInterface) {
      return;
    }
    foreach ($permissions as $permission) {
      $role->grantPermission($permission);
    }
    $role->save();
  }

}
