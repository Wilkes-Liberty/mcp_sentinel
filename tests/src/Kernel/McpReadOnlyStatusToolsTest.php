<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\tool\Exception\InputException;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Read-only status tools: success, denial, not-ready, no sensitive output.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpReadOnlyStatusToolsTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedRequestTrait;
  use UserCreationTrait;

  /**
   * A marker that must never appear in a tool result.
   */
  private const SECRET = 'S3CR3T-status-tool';

  /**
   * Tool ids under test in the base module.
   */
  private const TOOLS = [
    'mcp_sentinel_governance_status',
    'mcp_sentinel_effective_limits',
    'mcp_sentinel_audit_metrics',
    'mcp_sentinel_role_audit',
    'mcp_sentinel_urgent_conditions',
  ];

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'user', 'mcp_sentinel']);
    $this->enableRoleFallbackGovernance();

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->grantPermission('administer mcp sentinel');
    $role->save();
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $profile = McpPolicyProfile::load('default');
    $profile->set('roles', ['mcp_api'])->save();

    // First created user is uid 1 and bypasses permission checks.
    $this->createUser();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Runs a tool and returns it.
   */
  private function runTool(string $id, array $inputs = []): McpGovernedToolBase {
    $tool = $this->container->get('plugin.manager.tool')->createInstance($id);
    self::assertInstanceOf(McpGovernedToolBase::class, $tool);
    foreach ($inputs as $name => $value) {
      $tool->setInputValue($name, $value);
    }
    $tool->execute();
    return $tool;
  }

  /**
   * Each tool is discoverable and succeeds for a governed account.
   */
  public function testGovernedSuccess(): void {
    $account = $this->container->get('current_user')->getAccount();
    foreach (self::TOOLS as $id) {
      $tool = $this->runTool($id);
      self::assertTrue($tool->discoveryAccess($account)->isAllowed(), $id);
      self::assertTrue($tool->getResultStatus(), $id . ': ' . $tool->getResultMessage());
      $values = $tool->getResult()->getContextValues();
      self::assertNotEmpty($values, $id);
      self::assertStringNotContainsString(self::SECRET, (string) json_encode($values), $id);
    }
  }

  /**
   * Governance status reports the contract, including a not-ready reason code.
   */
  public function testGovernanceStatusReturnsReasonCode(): void {
    $tool = $this->runTool('mcp_sentinel_governance_status');
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    self::assertArrayHasKey('ready', $values);
    self::assertFalse($values['ready']);
    self::assertIsString($values['reason']);
    self::assertMatchesRegularExpression('/^[a-z_]+$/', $values['reason']);
  }

  /**
   * Effective limits are finite numbers for the acting profile.
   */
  public function testEffectiveLimitsAreNumeric(): void {
    $tool = $this->runTool('mcp_sentinel_effective_limits');
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    foreach ([
      'result_cap',
      'response_size_cap',
      'rate_limit_requests',
      'rate_limit_window',
      'page_budget',
      'page_window',
    ] as $key) {
      self::assertIsInt($values[$key], $key);
      self::assertGreaterThanOrEqual(0, $values[$key], $key);
    }
  }

  /**
   * Audit metrics cover the three fixed windows and omit top agents.
   */
  public function testAuditMetricsWindowsAndNoAgents(): void {
    $tool = $this->runTool('mcp_sentinel_audit_metrics');
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    $text = (string) json_encode($values);
    self::assertArrayHasKey('windows', $values);
    foreach (['24h', '7d', '30d'] as $window) {
      self::assertArrayHasKey($window, $values['windows']);
      self::assertArrayHasKey('counts', $values['windows'][$window]);
      self::assertArrayHasKey('allowed_vs_denied', $values['windows'][$window]);
      self::assertArrayHasKey('denied_reasons', $values['windows'][$window]);
      self::assertArrayHasKey('operation_mix', $values['windows'][$window]);
      self::assertArrayHasKey('webhook_health', $values['windows'][$window]);
    }
    self::assertStringNotContainsString('top_agents', $text);
    self::assertStringNotContainsString('"uid"', $text);
  }

  /**
   * Role audit requires the administer permission.
   */
  public function testRoleAuditRequiresAdminister(): void {
    $role = Role::load('mcp_api');
    $role->revokePermission('administer mcp sentinel')->save();
    $tool = $this->runTool('mcp_sentinel_role_audit');
    self::assertFalse($tool->getResultStatus());
    self::assertStringContainsString('refused', (string) $tool->getResultMessage());

    $role->grantPermission('administer mcp sentinel')->save();
    $tool = $this->runTool('mcp_sentinel_role_audit');
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    self::assertArrayHasKey('count', $values);
    self::assertArrayHasKey('violations', $values);
  }

  /**
   * Urgent conditions return codes and counts, never messages or URLs.
   */
  public function testUrgentConditionsAreCodesOnly(): void {
    $tool = $this->runTool('mcp_sentinel_urgent_conditions');
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $values = $tool->getResult()->getContextValues();
    $text = (string) json_encode($values);
    self::assertArrayHasKey('conditions', $values);
    self::assertArrayHasKey('anomalies', $values);
    self::assertStringNotContainsString('http', $text);
    self::assertStringNotContainsString('actor', $text);
    foreach ($values['conditions'] as $condition) {
      self::assertArrayHasKey('key', $condition);
      self::assertArrayHasKey('severity', $condition);
      self::assertArrayNotHasKey('message', $condition);
      self::assertArrayNotHasKey('url', $condition);
    }
  }

  /**
   * Anonymous callers are denied.
   */
  public function testAnonymousDenial(): void {
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
    foreach (self::TOOLS as $id) {
      $tool = $this->runTool($id);
      self::assertFalse($tool->discoveryAccess(new AnonymousUserSession())->isAllowed(), $id);
      self::assertFalse($tool->getResultStatus(), $id);
    }
  }

  /**
   * When audit is off, the readiness gate refuses the call.
   */
  public function testGovernanceNotReadyRefuses(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $account = $this->container->get('current_user')->getAccount();
    foreach (self::TOOLS as $id) {
      $tool = $this->container->get('plugin.manager.tool')->createInstance($id);
      self::assertInstanceOf(McpGovernedToolBase::class, $tool);
      self::assertFalse($tool->discoveryAccess($account)->isAllowed(), $id);
      $tool->execute();
      self::assertFalse($tool->getResultStatus(), $id);
      self::assertStringNotContainsString(self::SECRET, (string) $tool->getResultMessage(), $id);
    }
  }

  /**
   * An unknown input key is refused without echoing the value.
   */
  public function testUnknownInputRefusedWithoutEcho(): void {
    $marker = 'unexpected-input-qx';
    foreach (self::TOOLS as $id) {
      $tool = $this->container->get('plugin.manager.tool')->createInstance($id);
      self::assertInstanceOf(McpGovernedToolBase::class, $tool);
      try {
        $tool->setInputValue($marker, self::SECRET);
        self::fail($id . ' accepted an unknown input key.');
      }
      catch (InputException $exception) {
        self::assertStringNotContainsString(self::SECRET, $exception->getMessage(), $id);
      }
    }
  }

}
