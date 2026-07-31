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
    'system',
    'user',
    'field',
    'tool',
    'key',
    'serialization',
    'file',
    'image',
    'options',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_approval',
  ];

  /**
   * Frozen request time for deterministic expiry math.
   *
   * Advanced in tests via $this->now += N; the mocked datetime.time service
   * reads this property on each getRequestTime() call.
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

    // Kernel module enable may already install config/optional when deps are
    // satisfied. Creating again would throw EntityStorageException. Prefer the
    // shipped role; only create when optional install did not run.
    if (Role::load(McpBreakGlassManager::ROLE_ID) === NULL) {
      Role::create([
        'id' => McpBreakGlassManager::ROLE_ID,
        'label' => 'MCP break-glass admin',
        // Explicit FALSE: never rely on Role defaults for is_admin.
        'is_admin' => FALSE,
        // Must match ALLOWED_PERMISSIONS — grant refuse uses that constant.
        'permissions' => McpBreakGlassManager::ALLOWED_PERMISSIONS,
      ])->save();
    }

    // Freeze time so grant TTL / reaper expiry math is deterministic.
    // Rebind the manager after the mock: installConfig may already have
    // constructed services that captured the real clock.
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturnCallback(fn (): int => $this->now);
    $this->container->set('datetime.time', $time);
    $this->container->set('mcp_sentinel_approval.break_glass', new McpBreakGlassManager(
      $this->container->get('entity_type.manager'),
      $time,
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.audit_logger'),
    ));
  }

  /**
   * Returns the break-glass manager (container service with mocked clock).
   *
   * @return \Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager
   *   The manager under test.
   */
  private function manager(): McpBreakGlassManager {
    return $this->container->get('mcp_sentinel_approval.break_glass');
  }

  /**
   * Sorts a permission list for order-independent comparison.
   *
   * @param list<string> $permissions
   *   Permission machine names.
   *
   * @return list<string>
   *   Sorted copy.
   */
  private function sortedPermissions(array $permissions): array {
    sort($permissions);
    return $permissions;
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
   *
   * Guards the enterprise contract: least privilege (enumerated perms) and
   * separation of duties (approve stays off this role).
   */
  public function testBreakGlassRoleIsEnumeratedAndNotAdmin(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role, 'mcp_admin role must exist for break-glass tests.');
    $this->assertFalse($role->isAdmin(), 'Break-glass must not be is_admin.');
    $this->assertSame(
      $this->sortedPermissions(McpBreakGlassManager::ALLOWED_PERMISSIONS),
      $this->sortedPermissions($role->getPermissions()),
      'Role is the approved five-permission set.',
    );
    // Approve is a standing second-person control, not part of break-glass.
    $this->assertNotContains(
      'approve mcp sentinel operations',
      $role->getPermissions(),
      'Approve stays on a standing role — separation of duties.',
    );
  }

  /**
   * The optional config file on disk matches the grant-time allowlist constant.
   *
   * Prevents drift between ALLOWED_PERMISSIONS and the YAML new sites import.
   */
  public function testOptionalConfigYamlShipsApprovedList(): void {
    $path = $this->container->get('extension.list.module')
      ->getPath('mcp_sentinel_approval') . '/config/optional/user.role.mcp_admin.yml';
    $this->assertFileExists($path);
    $data = Yaml::decode((string) file_get_contents($path));
    $this->assertIsArray($data);
    $this->assertFalse($data['is_admin'], 'Shipped YAML must set is_admin: false.');
    $this->assertSame(
      $this->sortedPermissions(McpBreakGlassManager::ALLOWED_PERMISSIONS),
      $this->sortedPermissions($data['permissions']),
      'Shipped YAML permissions must match ALLOWED_PERMISSIONS.',
    );
    $this->assertNotContains(
      'approve mcp sentinel operations',
      $data['permissions'],
      'Shipped YAML must not include approve-ops.',
    );
  }

  /**
   * Grant refuses an is_admin mcp_admin role (fail closed).
   *
   * @covers ::grant
   */
  public function testGrantRefusesIsAdminRole(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    // Simulate a misconfigured site that left mcp_admin as superuser.
    $role->set('is_admin', TRUE);
    $role->save();

    $user = User::create(['name' => 'would_be_superuser', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertFalse($result['granted'], 'Grant must refuse is_admin mcp_admin.');
    $this->assertStringContainsString('is_admin', $result['message']);
    $this->assertSame(0, $result['expires'], 'Refused grants expire at 0.');

    $user = User::load($user->id());
    $this->assertNotNull($user);
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
    $this->assertNotNull($role);
    $role->set('is_admin', TRUE)->save();

    $this->container->get('module_handler')->loadInclude('mcp_sentinel_approval', 'install');
    $requirements = mcp_sentinel_approval_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_approval_mcp_admin_is_admin', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_approval_mcp_admin_is_admin']['severity'],
      'Status report must ERROR when mcp_admin is is_admin.',
    );
  }

  /**
   * Grant refuses when the break-glass role is missing (fail closed).
   *
   * @covers ::grant
   */
  public function testGrantRefusesMissingRole(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    // Site never imported optional config (or deleted the role).
    $role->delete();

    $user = User::create(['name' => 'no_role_site', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertFalse($result['granted'], 'Grant must refuse when mcp_admin is missing.');
    $this->assertStringContainsString('does not exist', $result['message']);

    $this->container->get('module_handler')->loadInclude('mcp_sentinel_approval', 'install');
    $requirements = mcp_sentinel_approval_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_approval_mcp_admin_missing', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_approval_mcp_admin_missing']['severity'],
      'Status report must ERROR when mcp_admin is missing.',
    );
  }

  /**
   * Grant refuses when the role holds a permission outside the allowlist.
   *
   * @covers ::grant
   * @covers ::permissionExtras
   */
  public function testGrantRefusesExtraPermissions(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    // Site widened break-glass past least privilege (escape-hatch example).
    $role->grantPermission('administer users')->save();

    $user = User::create(['name' => 'widened_role', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertFalse($result['granted'], 'Grant must refuse allowlist extras.');
    $this->assertStringContainsString('outside the break-glass allowlist', $result['message']);
    $this->assertStringContainsString('administer users', $result['message']);

    $user = User::load($user->id());
    $this->assertNotNull($user);
    $this->assertFalse(
      $user->hasRole(McpBreakGlassManager::ROLE_ID),
      'Widened break-glass must not be attached to the account.',
    );
  }

  /**
   * Grant refuses when approve-ops is on the role (separation of duties).
   *
   * @covers ::grant
   */
  public function testGrantRefusesApproveOpsOnBreakGlassRole(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->grantPermission('approve mcp sentinel operations')->save();

    $user = User::create(['name' => 'sod_break', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertFalse($result['granted']);
    $this->assertStringContainsString('approve mcp sentinel operations', $result['message']);
  }

  /**
   * A proper subset of the allowlist still grants (narrower is safer).
   *
   * @covers ::grant
   */
  public function testGrantAllowsSubsetOfAllowlist(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    // Drop one shipped shell permission; elevation remains within the ceiling.
    $role->revokePermission('view the administration theme')->save();
    $this->assertSame(
      ['view the administration theme'],
      McpBreakGlassManager::permissionMissing($role),
    );
    $this->assertSame([], McpBreakGlassManager::permissionExtras($role));

    $user = User::create(['name' => 'narrow_shell', 'status' => 1]);
    $user->save();

    $result = $this->manager()->grant((int) $user->id());
    $this->assertTrue($result['granted'], 'Subset of allowlist must still grant.');
  }

  /**
   * Status report ERRORs when the role holds allowlist extras.
   */
  public function testRequirementsErrorWhenRoleHasExtraPermissions(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->grantPermission('administer users')->save();

    $this->container->get('module_handler')->loadInclude('mcp_sentinel_approval', 'install');
    $requirements = mcp_sentinel_approval_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_approval_mcp_admin_extra_permissions', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_approval_mcp_admin_extra_permissions']['severity'],
    );
    $this->assertStringContainsString(
      'administer users',
      (string) $requirements['mcp_sentinel_approval_mcp_admin_extra_permissions']['description'],
    );
  }

  /**
   * Status report WARNINGs when the role is missing shipped allowlist perms.
   */
  public function testRequirementsWarningWhenRoleMissingShippedPermissions(): void {
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->revokePermission('access site reports')->save();

    $this->container->get('module_handler')->loadInclude('mcp_sentinel_approval', 'install');
    $requirements = mcp_sentinel_approval_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_approval_mcp_admin_missing_permissions', $requirements);
    $this->assertSame(
      REQUIREMENT_WARNING,
      $requirements['mcp_sentinel_approval_mcp_admin_missing_permissions']['severity'],
    );
    $this->assertStringContainsString(
      'access site reports',
      (string) $requirements['mcp_sentinel_approval_mcp_admin_missing_permissions']['description'],
    );
    // Incomplete shell is not ERROR-level (grant still allowed).
    $this->assertArrayNotHasKey('mcp_sentinel_approval_mcp_admin_extra_permissions', $requirements);
  }

  /**
   * Active grants are force-revoked when the role gains allowlist extras.
   *
   * @covers ::reapUnsafePosture
   * @covers ::findActiveGrantFor
   */
  public function testReapUnsafePostureRevokesActiveGrantsOnExtras(): void {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 3600)->save();
    $user = User::create(['name' => 'live_holder', 'status' => 1]);
    $user->save();
    $uid = (int) $user->id();

    $this->assertTrue($this->manager()->grant($uid)['granted']);
    $user = User::load($uid);
    $this->assertNotNull($user);
    $this->assertTrue($user->hasRole(McpBreakGlassManager::ROLE_ID));
    $this->assertNotNull($this->manager()->findActiveGrantFor($uid));

    // Widen the role under the live grant — grant-time seal no longer applies.
    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->grantPermission('administer users')->save();

    $this->assertSame(1, $this->manager()->reapUnsafePosture(), 'Live grant must be force-revoked.');
    $user = User::load($uid);
    $this->assertNotNull($user);
    $this->assertFalse(
      $user->hasRole(McpBreakGlassManager::ROLE_ID),
      'Role must be removed when posture is unsafe.',
    );
    $this->assertNull($this->manager()->findActiveGrantFor($uid));

    $revokedRows = (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'mcp_admin_revoked')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertGreaterThanOrEqual(1, $revokedRows, 'Force-revoke must leave an audit row.');
  }

  /**
   * Narrower-than-allowlist alone does not force-revoke (WARNING only).
   *
   * @covers ::reapUnsafePosture
   */
  public function testReapUnsafePostureIgnoresNarrowRole(): void {
    $this->config('mcp_sentinel_approval.settings')->set('break_glass_ttl_seconds', 3600)->save();
    $user = User::create(['name' => 'narrow_live', 'status' => 1]);
    $user->save();
    $uid = (int) $user->id();
    $this->assertTrue($this->manager()->grant($uid)['granted']);

    $role = Role::load(McpBreakGlassManager::ROLE_ID);
    $this->assertNotNull($role);
    $role->revokePermission('view the administration theme')->save();

    $this->assertSame(0, $this->manager()->reapUnsafePosture(), 'Subset must not force-revoke.');
    $user = User::load($uid);
    $this->assertNotNull($user);
    $this->assertTrue($user->hasRole(McpBreakGlassManager::ROLE_ID));
  }

}
