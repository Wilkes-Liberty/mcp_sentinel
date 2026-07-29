<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpRoleAssertions;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for escape-hatch permission assertions (issue #65).
 *
 * The case these come from: a live `mcp_content_editor` role held
 * `bypass file gate` alongside `access mcp server` and 18 profile permissions.
 * File Gate declines its veto for any account holding that permission, so the
 * agent role could fetch gated private files straight off `/system/files/…` —
 * no MCP request, therefore no policy, no redaction and no audit row. Nothing
 * in the module could see it.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpRoleAssertions
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpRoleAssertions::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRoleAssertionsTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * The service under test.
   */
  private McpRoleAssertions $assertions;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    // Role saves are watched by McpConfigSaveSubscriber::onRoleSave(), which
    // records a violation in the audit log — so these tests need the table.
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_audit_log']);
    $this->installConfig(['mcp_sentinel', 'user']);
    $this->assertions = $this->container->get('mcp_sentinel.role_assertions');
  }

  /**
   * Creates a governed role and points the settings at it.
   *
   * @param array $values
   *   Role entity values to merge.
   *
   * @return \Drupal\user\Entity\Role
   *   The saved role.
   */
  private function governedRole(array $values = []): Role {
    $role = Role::create($values + ['id' => 'mcp_agent', 'label' => 'MCP agent']);
    $role->save();
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', [$role->id()])
      ->save();
    return $role;
  }

  /**
   * Ensures a profile exists that governs everything by default.
   */
  private function defaultProfile(array $values = []): McpPolicyProfile {
    $profile = McpPolicyProfile::load('default');
    if ($profile === NULL) {
      $profile = McpPolicyProfile::create(['id' => 'default', 'label' => 'Default']);
    }
    foreach ($values as $key => $value) {
      $profile->set($key, $value);
    }
    $profile->save();
    return $profile;
  }

  /**
   * A clean governed role reports nothing.
   */
  public function testCleanRoleHasNoViolations(): void {
    $this->defaultProfile();
    $role = $this->governedRole();
    $role->grantPermission('access content')->save();

    $this->assertSame([], $this->assertions->violations());
  }

  /**
   * The live case: a governed role directly holding a forbidden permission.
   *
   * Uses 'administer users' rather than the `bypass file gate` from the
   * original incident because core strips permissions no installed module
   * defines (Role::calculateDependencies()), and file_gate is not part of this
   * test's module set. That is not a weaker test — it is the only shape the
   * defect can take on a real site, since the role can only carry the string
   * while the module defining it is installed, which is exactly when the
   * bypass is reachable.
   */
  public function testForbiddenPermissionHeldDirectlyIsReported(): void {
    $this->defaultProfile();
    $role = $this->governedRole();
    $role->grantPermission('administer users')->save();

    $violations = $this->assertions->violations();
    $this->assertCount(1, $violations);
    $this->assertSame('mcp_agent', $violations[0]['role']);
    $this->assertSame('administer users', $violations[0]['permission']);
    $this->assertSame(McpRoleAssertions::VIOLATION_FORBIDDEN, $violations[0]['type']);
    $this->assertSame('direct', $violations[0]['via']);
    $this->assertStringContainsString('administer users', $this->assertions->describe($violations[0]));
  }

  /**
   * A bypass granted to 'authenticated' is held by every governed role.
   *
   * The failure mode a naive check misses: the governed role's own permission
   * array is empty, so reading only that reports the site clean while every
   * logged-in account — the agent included — holds the bypass.
   */
  public function testPermissionInheritedFromAuthenticatedIsReported(): void {
    $this->defaultProfile();
    $this->governedRole();

    $authenticated = Role::load('authenticated');
    $authenticated->grantPermission('bypass node access')->save();

    $violations = $this->assertions->violations();
    $this->assertCount(1, $violations);
    $this->assertSame('bypass node access', $violations[0]['permission']);
    $this->assertSame('authenticated', $violations[0]['via']);
    $this->assertStringContainsString(
      "'authenticated' role grants it to every logged-in user",
      $this->assertions->describe($violations[0]),
    );
  }

  /**
   * An is_admin governed role is its own violation, not a permission scan.
   *
   * Its permission array is empty by design, so enumerating it proves nothing —
   * it implicitly holds every permission the site defines, including ones a
   * module installed tomorrow will add.
   */
  public function testAdminRoleIsReportedWithoutEnumeration(): void {
    $this->defaultProfile();
    $role = $this->governedRole(['is_admin' => TRUE]);

    $this->assertSame([], $role->getPermissions(), 'Precondition: an is_admin role lists no permissions.');

    $violations = $this->assertions->violations();
    $this->assertCount(1, $violations);
    $this->assertSame(McpRoleAssertions::VIOLATION_IS_ADMIN, $violations[0]['type']);
    $this->assertSame('*', $violations[0]['permission']);
    $this->assertTrue($this->assertions->isAdminRole('mcp_agent'));
  }

  /**
   * An admin 'authenticated' role makes every governed role an admin.
   */
  public function testAdminAuthenticatedRoleIsReported(): void {
    $this->defaultProfile();
    $this->governedRole();

    $authenticated = Role::load('authenticated');
    $authenticated->set('is_admin', TRUE)->save();

    $violations = $this->assertions->violations();
    $this->assertCount(1, $violations);
    $this->assertSame(McpRoleAssertions::VIOLATION_IS_ADMIN, $violations[0]['type']);
    $this->assertSame('authenticated', $violations[0]['via']);
  }

  /**
   * An acknowledgement suppresses one role/permission pair, and only that pair.
   */
  public function testAcknowledgementSuppressesTheGrantItNames(): void {
    $this->defaultProfile([
      'acknowledged_role_permissions' => ['mcp_agent:administer users'],
    ]);
    $role = $this->governedRole();
    $role->grantPermission('administer users')->save();

    $this->assertSame([], $this->assertions->violations());

    // A different forbidden permission is still reported: the acknowledgement
    // records one decision, it does not switch the assertion off.
    $role->grantPermission('bypass node access')->save();
    $violations = $this->assertions->violations();
    $this->assertCount(1, $violations);
    $this->assertSame('bypass node access', $violations[0]['permission']);
  }

  /**
   * An acknowledgement for a different role does not transfer.
   */
  public function testAcknowledgementIsScopedToItsRole(): void {
    $this->defaultProfile([
      'acknowledged_role_permissions' => ['some_other_role:administer users'],
    ]);
    $role = $this->governedRole();
    $role->grantPermission('administer users')->save();

    $this->assertCount(1, $this->assertions->violations());
  }

  /**
   * The forbidden list is per-profile configuration, not hardcoded.
   */
  public function testForbiddenListIsProfileConfiguration(): void {
    $this->defaultProfile(['forbidden_role_permissions' => ['administer permissions']]);
    $role = $this->governedRole();
    $role->grantPermission('administer permissions')->save();
    // On the shipped list, but not on this profile's — so not reported here.
    $role->grantPermission('administer users')->save();

    $violations = $this->assertions->violations();
    $this->assertCount(1, $violations, 'Only the configured list is asserted.');
    $this->assertSame('administer permissions', $violations[0]['permission']);
  }

  /**
   * The shipped default profile carries the protective list out of the box.
   */
  public function testShippedProfileAssertsTheDefaultList(): void {
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile, 'The default profile ships with the module.');
    $this->assertSame(
      McpPolicyProfile::DEFAULT_FORBIDDEN_ROLE_PERMISSIONS,
      $profile->getForbiddenRolePermissions(),
      'An operator inherits the protection without authoring it.',
    );
  }

  /**
   * An ungoverned role holding a forbidden permission is not this check's job.
   */
  public function testUngovernedRolesAreNotReported(): void {
    $this->defaultProfile();
    $this->governedRole();

    $other = Role::create(['id' => 'editor', 'label' => 'Editor']);
    $other->grantPermission('administer users')->save();

    $this->assertSame([], $this->assertions->violations());
  }

}
