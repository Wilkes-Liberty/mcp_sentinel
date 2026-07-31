<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Kernel;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Serialization\Yaml;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the time-boxed mcp_admin break-glass model.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpBreakGlassTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'tool', 'key', 'serialization',
    'file', 'image', 'options',
    'consumers', 'simple_oauth', 'encrypt',
    'audit_chain', 'mcp_sentinel', 'mcp_sentinel_approval',
  ];

  /**
   * A frozen-time test clock.
   */
  private int $now = 1000000;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->installEntitySchema('mcp_approval_request');
    $this->installEntitySchema('mcp_admin_grant');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel', 'mcp_sentinel_approval']);
    // Prefer the shipped optional role when module enable already installed it;
    // otherwise create the same least-privilege set for grant/reap assertions.
    if (Role::load(McpBreakGlassManager::ROLE_ID) === NULL) {
      Role::create([
        'id' => McpBreakGlassManager::ROLE_ID,
        'label' => 'MCP break-glass admin',
        'is_admin' => FALSE,
        'permissions' => [
          'access administration pages',
          'view the administration theme',
          'access site reports',
          'view mcp sentinel audit log',
          'administer mcp sentinel',
        ],
      ])->save();
    }

    // Freeze time so expiry math is deterministic.
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturnCallback(fn (): int => $this->now);
    $this->container->set('datetime.time', $time);
  }

  /**
   * Returns the break-glass manager (rebuilt to pick up the mocked clock).
   */
  private function manager(): McpBreakGlassManager {
    return $this->container->get('mcp_sentinel_approval.break_glass');
  }

  /**
   * Granting adds the role and records a grant; cron later reaps it.
   *
   * @covers ::grant
   * @covers ::reapExpired
   */
  public function testGrantThenExpireRevokes(): void {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 100)->save();
    $user = User::create(['name' => 'breakglass', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertTrue($result['granted']);

    $user = User::load($user->id());
    $this->assertTrue($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role granted.');

    // Before expiry: reaper is a no-op.
    $this->now += 50;
    $this->assertSame(0, $this->manager()->reapExpired());
    $user = User::load($user->id());
    $this->assertTrue($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role still held before expiry.');

    // After expiry: reaper removes the role and marks the grant revoked.
    $this->now += 100;
    $this->assertSame(1, $this->manager()->reapExpired());
    $user = User::load($user->id());
    $this->assertFalse($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role revoked after expiry.');
  }

  /**
   * An overlapping grant keeps the role when the earlier one expires.
   *
   * The reaper asks hasOtherActiveGrant() before removing the role, and that
   * question is answered by a second entity query with its own 'revoked'
   * condition. Nothing exercised it, so the same bind defect that made
   * reapExpired() a silent no-op would have made this one answer "no other
   * grant" every time -- and the reaper would have pulled the role out from
   * under a grant that had not expired yet. Renewing a break-glass grant
   * before the first lapses is the ordinary case, not an exotic one.
   *
   * @covers ::reapExpired
   */
  public function testStillActiveOverlappingGrantKeepsTheRole(): void {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 100)->save();
    $user = User::create(['name' => 'overlap', 'status' => 1]);
    $user->save();
    $uid = (int) $user->id();

    // First grant: expires at now + 100.
    $this->assertTrue($this->manager()->grant($uid)['granted']);

    // Renewed 50s later, so the second grant runs to now + 150.
    $this->now += 50;
    $this->assertTrue($this->manager()->grant($uid)['granted']);

    // Past the first expiry but not the second: the lapsed grant is reaped,
    // and the role stays because the renewal still covers this user.
    $this->now += 60;
    $this->assertSame(1, $this->manager()->reapExpired(), 'The lapsed grant is revoked.');
    $user = User::load($uid);
    $this->assertTrue(
      $user->hasRole(McpBreakGlassManager::ROLE_ID),
      'The role survives while a later grant is still active.',
    );

    // Past the second expiry: nothing covers the user, so the role goes.
    $this->now += 100;
    $this->assertSame(1, $this->manager()->reapExpired(), 'The renewal is revoked in turn.');
    $user = User::load($uid);
    $this->assertFalse($user->hasRole(McpBreakGlassManager::ROLE_ID), 'Role revoked once no grant covers the user.');
  }

  /**
   * Granting to a non-existent user fails closed.
   *
   * @covers ::grant
   */
  public function testGrantUnknownUserFails(): void {
    $result = $this->manager()->grant(99999);
    $this->assertFalse($result['granted']);
  }

  /**
   * The break-glass role under test is non-admin and holds the approved set.
   */
  public function testBreakGlassRoleIsEnumeratedAndNotAdmin(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $this->assertFalse($role->isAdmin(), 'Break-glass must not be is_admin.');
    $expected = [
      'access administration pages',
      'view the administration theme',
      'access site reports',
      'view mcp sentinel audit log',
      'administer mcp sentinel',
    ];
    $held = $role->getPermissions();
    sort($expected);
    sort($held);
    $this->assertSame($expected, $held, 'Role is the approved five-permission set.');
    $this->assertNotContains(
      'approve mcp sentinel operations',
      $held,
      'Approve stays on a standing role — separation of duties.',
    );
  }

  /**
   * The optional config file on disk matches the approved enterprise default.
   */
  public function testOptionalConfigYamlShipsApprovedList(): void {
    $path = $this->container->get('extension.list.module')
      ->getPath('mcp_sentinel_approval') . '/config/optional/user.role.mcp_admin.yml';
    $this->assertFileExists($path);
    $data = Yaml::decode((string) file_get_contents($path));
    $this->assertFalse($data['is_admin']);
    $expected = [
      'access administration pages',
      'view the administration theme',
      'access site reports',
      'view mcp sentinel audit log',
      'administer mcp sentinel',
    ];
    $held = $data['permissions'];
    sort($expected);
    sort($held);
    $this->assertSame($expected, $held);
    $this->assertNotContains('approve mcp sentinel operations', $held);
  }

  /**
   * Grant refuses an is_admin mcp_admin role (fail closed).
   *
   * @covers ::grant
   */
  public function testGrantRefusesIsAdminRole(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->set('is_admin', TRUE);
    $role->save();

    $user = User::create(['name' => 'would_be_superuser', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertFalse($result['granted']);
    $this->assertStringContainsString('is_admin', $result['message']);

    $user = User::load($user->id());
    $this->assertFalse(
      $user->hasRole(McpBreakGlassManager::ROLE_ID),
      'is_admin break-glass must not be attached to the account.',
    );
  }

  /**
   * Status report errors when the break-glass role is is_admin.
   */
  public function testRequirementsErrorWhenRoleIsAdmin(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $role->set('is_admin', TRUE)->save();

    $this->container->get('module_handler')->loadInclude('mcp_sentinel_approval', 'install');
    $requirements = mcp_sentinel_approval_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_approval_mcp_admin_is_admin', $requirements);
    $this->assertSame(REQUIREMENT_ERROR, $requirements['mcp_sentinel_approval_mcp_admin_is_admin']['severity']);
  }

  /**
   * Grant refuses when the break-glass role is missing (fail closed).
   *
   * @covers ::grant
   */
  public function testGrantRefusesMissingRole(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->delete();

    $user = User::create(['name' => 'no_role_site', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertFalse($result['granted']);
    $this->assertStringContainsString('does not exist', $result['message']);

    $this->container->get('module_handler')->loadInclude('mcp_sentinel_approval', 'install');
    $requirements = mcp_sentinel_approval_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_approval_mcp_admin_missing', $requirements);
    $this->assertSame(REQUIREMENT_ERROR, $requirements['mcp_sentinel_approval_mcp_admin_missing']['severity']);
  }

}
