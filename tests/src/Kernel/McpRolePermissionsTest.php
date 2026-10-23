<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\McpRolePermissions;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel coverage for the portable role-permission grant helper.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\McpRolePermissions
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpRolePermissions::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRolePermissionsTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['user']);
  }

  /**
   * Granting permissions persists them on the named role.
   */
  public function testGrantAddsPermissionsAndSaves(): void {
    Role::create([
      'id' => 'mcp_compat',
      'label' => 'Compat',
    ])->save();

    McpRolePermissions::grant('mcp_compat', [
      'access content',
      'access user profiles',
    ]);

    $role = Role::load('mcp_compat');
    $this->assertNotNull($role);
    $this->assertTrue($role->hasPermission('access content'));
    $this->assertTrue($role->hasPermission('access user profiles'));
  }

  /**
   * A missing role is a no-op, matching user_role_grant_permissions().
   */
  public function testGrantIsNoOpForMissingRole(): void {
    McpRolePermissions::grant('does_not_exist', ['access content']);
    $this->assertNull(Role::load('does_not_exist'));
  }

}
