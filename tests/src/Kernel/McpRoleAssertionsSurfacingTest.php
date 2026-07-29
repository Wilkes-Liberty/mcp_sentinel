<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Surfacing tests for escape-hatch assertions (issue #65).
 *
 * A finding nobody sees is not a control. These cover the three places a
 * violation has to appear — the dashboard banner, the status report, and the
 * deploy-time exit code — plus the recurrence guard on role save, which is what
 * stops the original incident silently coming back.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRoleAssertionsSurfacingTest extends KernelTestBase {

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
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installConfig(['audit_chain', 'mcp_sentinel', 'user']);
  }

  /**
   * Creates a governed role holding a forbidden permission.
   */
  private function violatingRole(): Role {
    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP agent']);
    $role->save();
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_agent'])
      ->save();
    $role->grantPermission('administer users')->save();
    return $role;
  }

  /**
   * The dashboard banner raises it as critical.
   *
   * Critical rather than warning: the other conditions say a control is
   * misconfigured; this one says a control that looks configured is not a
   * boundary at all.
   */
  public function testFiresAsCriticalUrgentCondition(): void {
    $this->violatingRole();

    $conditions = $this->container->get('mcp_sentinel.urgent_conditions')->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('role_escape_hatch', $keys);

    foreach ($conditions as $condition) {
      if ($condition['key'] === 'role_escape_hatch') {
        $this->assertSame('critical', $condition['severity']);
        $this->assertStringContainsString('administer users', $condition['message']);
      }
    }
  }

  /**
   * A clean site raises nothing.
   */
  public function testCleanSiteRaisesNoCondition(): void {
    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP agent']);
    $role->save();
    $this->config('mcp_sentinel.settings')->set('governed_roles', ['mcp_agent'])->save();

    $keys = array_column(
      $this->container->get('mcp_sentinel.urgent_conditions')->evaluate(),
      'key',
    );
    $this->assertNotContains('role_escape_hatch', $keys);
  }

  /**
   * The status report reports it at ERROR.
   */
  public function testStatusReportRaisesAnError(): void {
    $this->violatingRole();

    $requirements = $this->runtimeRequirements();

    $this->assertArrayHasKey('mcp_sentinel_role_escape_hatch', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_role_escape_hatch']['severity'],
    );
  }

  /**
   * Saving a role that gains a forbidden permission is recorded immediately.
   *
   * The recurrence guard: the original grant arrived in an exported role
   * config and nothing noticed. This does not block the save — that would put
   * the module in the way of an operator changing their own permissions, and
   * would break config import — it records it.
   */
  public function testRoleSaveRecordsTheGrant(): void {
    $this->violatingRole();

    $rows = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['operation'])
      ->condition('l.operation', 'role_escape_hatch')
      ->execute()
      ->fetchCol();

    $this->assertNotEmpty($rows, 'A role gaining a forbidden permission is written to the audit chain.');
  }

  /**
   * Granting the bypass to 'authenticated' is caught on that role's save.
   *
   * The governed role's own config never changes here, so a listener watching
   * only the governed role would miss it entirely — while every logged-in
   * account, agent included, gains the permission.
   */
  public function testAuthenticatedRoleSaveIsAttributedToGovernedRoles(): void {
    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP agent']);
    $role->save();
    $this->config('mcp_sentinel.settings')->set('governed_roles', ['mcp_agent'])->save();

    Role::load('authenticated')->grantPermission('bypass node access')->save();

    $rows = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id'])
      ->condition('l.operation', 'role_escape_hatch')
      ->execute()
      ->fetchCol();

    $this->assertSame(['mcp_agent'], $rows, 'The finding is recorded against the governed role that inherits it.');
  }

  /**
   * An unrelated role save neither records nor breaks.
   */
  public function testUnrelatedRoleSaveIsQuiet(): void {
    $role = Role::create(['id' => 'editor', 'label' => 'Editor']);
    $role->grantPermission('access content')->save();

    $count = (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'role_escape_hatch')
      ->countQuery()
      ->execute()
      ->fetchField();

    $this->assertSame(0, $count);
  }

  /**
   * The acknowledgement path clears every surface at once.
   */
  public function testAcknowledgementClearsTheSurfaces(): void {
    $this->violatingRole();

    $profile = McpPolicyProfile::load('default');
    $profile->set('acknowledged_role_permissions', ['mcp_agent:administer users'])->save();

    $keys = array_column(
      $this->container->get('mcp_sentinel.urgent_conditions')->evaluate(),
      'key',
    );
    $this->assertNotContains('role_escape_hatch', $keys);

    $requirements = $this->runtimeRequirements();
    $this->assertArrayNotHasKey('mcp_sentinel_role_escape_hatch', $requirements);
  }

  /**
   * Invokes hook_requirements() in a way that works on every supported core.
   *
   * The hook lives in the .install file, which ModuleHandler does not load for
   * invoke(). On Drupal 11 another test had usually loaded it already and this
   * happened to work; on 10.6 it returned NULL and the assertion died on a
   * non-array. Load it explicitly instead of depending on whatever ran first.
   *
   * @return array
   *   The runtime requirements.
   */
  private function runtimeRequirements(): array {
    require_once $this->root . '/core/includes/install.inc';
    \Drupal::moduleHandler()->loadInclude('mcp_sentinel', 'install');
    return (array) \Drupal::moduleHandler()->invoke('mcp_sentinel', 'requirements', ['runtime']);
  }

}
