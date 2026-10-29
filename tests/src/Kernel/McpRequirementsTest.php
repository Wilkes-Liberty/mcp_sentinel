<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for mcp_sentinel_requirements() (the fail-loud guard).
 *
 * Verifies that the runtime status-report check warns when the module is
 * enabled but governance can never engage (no channel can fire, or no policy
 * profile exists), and stays silent when governance is properly wired. The
 * check mirrors how McpOauthContext::isAgentChannel() and McpPolicyResolver
 * actually decide, so the assertions track real governance behaviour.
 *
 * When the source-contract ERROR already names that same gap, the hook
 * keeps both severities on one ERROR row instead of repeating it as a
 * WARNING. Distinct gaps stay two rows.
 *
 * Approach mirrors McpUpdateHookChainTest: the .install file is loaded directly
 * and the hook function is invoked, simulating each config end-state in turn.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRequirementsTest extends KernelTestBase {

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
    // The warning the hook builds renders a settings-page link via
    // Url::fromRoute(), which resolves path aliases — install the path_alias
    // schema so that lookup has its table in the kernel test.
    $this->installEntitySchema('path_alias');
    $this->installConfig(['mcp_sentinel']);

    // hook_requirements() uses the REQUIREMENT_* severity constants, which are
    // defined in core/includes/install.inc. Drupal loads that file before
    // running requirements at runtime, but a kernel test invoking the hook
    // directly must load it explicitly.
    require_once \Drupal::root() . '/core/includes/install.inc';

    // Load the .install file so mcp_sentinel_requirements() is available.
    // Resolve the module path dynamically — the module is not always at
    // modules/contrib/ (e.g. on Drupal.org CI it lives at the project root).
    require_once \Drupal::root() . '/' . \Drupal::service('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';
  }

  /**
   * The non-runtime phases never emit the warning.
   */
  public function testNonRuntimePhaseReturnsNothing(): void {
    $this->assertSame([], mcp_sentinel_requirements('install'));
    $this->assertSame([], mcp_sentinel_requirements('update'));
  }

  /**
   * A fresh, properly-wired install emits no warning.
   *
   * The shipped defaults populate agent_scopes and install the 'default' policy
   * profile, so governance can engage and the guard stays silent.
   */
  public function testWiredInstallHasNoWarning(): void {
    // Sanity: the install defaults are what the guard treats as "wired".
    $config = $this->config('mcp_sentinel.settings');
    $this->assertTrue((bool) $config->get('enabled'));
    $this->assertNotEmpty($config->get('agent_scopes'));
    $this->assertNotNull(McpPolicyProfile::load('default'));

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_not_governing', $requirements);
    $this->assertArrayNotHasKey('mcp_sentinel_spoofchecker', $requirements);
  }

  /**
   * Disabled module emits no warning even when nothing is wired.
   */
  public function testDisabledModuleHasNoWarning(): void {
    $this->config('mcp_sentinel.settings')
      ->set('enabled', FALSE)
      ->set('agent_scopes', [])
      ->set('agent_oauth_clients', [])
      ->save();
    $this->deleteAllProfiles();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_not_governing', $requirements);
  }

  /**
   * Enabled but no channel can ever fire → warning.
   *
   * Empty agent_scopes + empty agent_oauth_clients means isAgentChannel() can
   * never return TRUE, and with the role fallback off nothing else governs.
   */
  public function testEnabledNoChannelWarns(): void {
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', [])
      ->set('agent_oauth_clients', [])
      ->set('governed_role_fallback', FALSE)
      ->save();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_not_governing', $requirements);
    $this->assertSame(
      REQUIREMENT_WARNING,
      $requirements['mcp_sentinel_not_governing']['severity']
    );
    // Kernel tests do not enable mcp_sentinel_server, so the contract ERROR
    // is server_module_missing — a different gap from empty scopes. Two
    // problems stay two rows; folding here would hide the WARNING.
    $this->assertArrayHasKey('mcp_sentinel_contract_not_ready', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_contract_not_ready']['severity']
    );
    $this->assertStringContainsString(
      'server_module_missing',
      (string) $requirements['mcp_sentinel_contract_not_ready']['value']
    );
  }

  /**
   * Configured agent_scopes alone clears the channel half of the check.
   *
   * With a scope configured and the default profile present, governance can
   * engage, so the guard is silent.
   */
  public function testAgentScopesWiresChannel(): void {
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', ['mcp_read'])
      ->set('agent_oauth_clients', [])
      ->save();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_not_governing', $requirements);
  }

  /**
   * Setting agent_oauth_clients alone clears the channel half of the check.
   */
  public function testAgentOauthClientsWiresChannel(): void {
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', [])
      ->set('agent_oauth_clients', ['mcp-agent-prod'])
      ->save();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_not_governing', $requirements);
  }

  /**
   * The role fallback only counts when enabled AND a usable role is set.
   *
   * 'authenticated'/'anonymous' are forbidden (they would capture all traffic),
   * so a fallback configured only with those roles cannot govern → warning.
   * A non-forbidden governed role with the fallback on clears the check.
   */
  public function testRoleFallbackChannelMirrorsResolver(): void {
    // Forbidden role only → still cannot govern → warning.
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', [])
      ->set('agent_oauth_clients', [])
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['authenticated'])
      ->save();
    $this->assertArrayHasKey(
      'mcp_sentinel_not_governing',
      mcp_sentinel_requirements('runtime')
    );

    // A usable governed role with the fallback on → governance can engage.
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $this->assertArrayNotHasKey(
      'mcp_sentinel_not_governing',
      mcp_sentinel_requirements('runtime')
    );
  }

  /**
   * Channel wired but no policy profile → warning.
   *
   * Even a governed request resolves to no profile, so no gate is applied;
   * McpPolicyResolver::resolve() returns NULL. The guard must warn.
   */
  public function testNoPolicyProfileWarns(): void {
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', ['mcp_read'])
      ->save();
    $this->deleteAllProfiles();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_not_governing', $requirements);
    $this->assertSame(
      REQUIREMENT_WARNING,
      $requirements['mcp_sentinel_not_governing']['severity']
    );
    // Scopes are set, so the contract ERROR is still the missing server
    // module, not active_profile_missing. That is a second problem, so
    // the WARNING row stays.
    $this->assertArrayHasKey('mcp_sentinel_contract_not_ready', $requirements);
    $this->assertStringContainsString(
      'server_module_missing',
      (string) $requirements['mcp_sentinel_contract_not_ready']['value']
    );
  }

  /**
   * Empty scopes that the contract already names share one ERROR row.
   *
   * Companion modules are stubbed present so the evaluator can reach
   * agent_scopes_missing. Both severities stay on that row; the WARNING
   * key is not repeated. The row stays ERROR so it cannot sit as
   * warning-only.
   */
  public function testOverlappingEmptyScopesShareOneRow(): void {
    $this->stubCompanionsEnabled();
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', [])
      ->set('agent_oauth_clients', [])
      ->set('governed_role_fallback', FALSE)
      ->save();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_contract_not_ready', $requirements);
    $this->assertArrayNotHasKey('mcp_sentinel_not_governing', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_contract_not_ready']['severity']
    );
    $value = (string) $requirements['mcp_sentinel_contract_not_ready']['value'];
    $this->assertStringContainsString('ERROR:', $value);
    $this->assertStringContainsString('WARNING:', $value);
    $this->assertStringContainsString('agent_scopes_missing', $value);
    $this->assertStringContainsString('Enabled but not governing', $value);
    $description = $requirements['mcp_sentinel_contract_not_ready']['description'];
    $this->assertIsArray($description);
    $this->assertStringContainsString('same gap', $description['#prefix']);
    $this->assertNotEmpty($description['#items']);
  }

  /**
   * A missing profile the contract already names shares one ERROR row.
   */
  public function testOverlappingMissingProfileSharesOneRow(): void {
    $this->stubCompanionsEnabled();
    $this->installEntitySchema('consumer');
    // simple_oauth queries oauth2_token when a consumer is saved.
    $this->installEntitySchema('oauth2_token');
    $owner = User::create([
      'name' => 'mcp_status_report_agent',
      'status' => 1,
    ]);
    $owner->save();
    Consumer::create([
      'client_id' => 'mcp-status-report-client',
      'label' => 'Status report client',
      'owner_id' => $owner->id(),
      'user_id' => $owner->id(),
      'secret' => 'not-echoed',
      'confidential' => TRUE,
      'status' => 1,
    ])->save();
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', ['mcp_read'])
      ->set('agent_oauth_clients', ['mcp-status-report-client'])
      ->set('governed_role_fallback', FALSE)
      ->save();
    $this->deleteAllProfiles();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_contract_not_ready', $requirements);
    $this->assertArrayNotHasKey('mcp_sentinel_not_governing', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_contract_not_ready']['severity']
    );
    $value = (string) $requirements['mcp_sentinel_contract_not_ready']['value'];
    $this->assertStringContainsString('ERROR:', $value);
    $this->assertStringContainsString('WARNING:', $value);
    $this->assertStringContainsString('active_profile_missing', $value);
  }

  /**
   * Empty scopes plus a missing profile keep the leftover WARNING row.
   *
   * The contract names agent_scopes_missing first, so the channel WARNING
   * folds into that ERROR. No profile is a second problem and stays on
   * mcp_sentinel_not_governing. One row per problem.
   */
  public function testPartialOverlapKeepsTheLeftoverWarning(): void {
    $this->stubCompanionsEnabled();
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('agent_scopes', [])
      ->set('agent_oauth_clients', [])
      ->set('governed_role_fallback', FALSE)
      ->save();
    $this->deleteAllProfiles();

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_contract_not_ready', $requirements);
    $this->assertArrayHasKey('mcp_sentinel_not_governing', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_contract_not_ready']['severity']
    );
    $this->assertSame(
      REQUIREMENT_WARNING,
      $requirements['mcp_sentinel_not_governing']['severity']
    );
    $this->assertStringContainsString(
      'agent_scopes_missing',
      (string) $requirements['mcp_sentinel_contract_not_ready']['value']
    );
    $this->assertStringContainsString(
      'WARNING:',
      (string) $requirements['mcp_sentinel_contract_not_ready']['value']
    );
    $items = $requirements['mcp_sentinel_not_governing']['description']['#items'];
    $this->assertCount(1, $items);
    $this->assertStringContainsString('policy profile', (string) $items[0]);
  }

  /**
   * Rebuilds readiness so companion modules look enabled.
   *
   * Kernel tests do not enable mcp_sentinel_server, the tool bridge, or
   * mcp_server_oauth. The live evaluator therefore stops at
   * server_module_missing before it can name the overlapping reasons.
   * Swap in an evaluator that treats those companions as present so the
   * hook can reach agent_scopes_missing and active_profile_missing.
   */
  private function stubCompanionsEnabled(): void {
    $modules = $this->createMock(ModuleHandlerInterface::class);
    $modules->method('moduleExists')->willReturnCallback(
      static function (string $name): bool {
        return in_array($name, [
          'audit_chain',
          'mcp_sentinel_server',
          'mcp_server_tool_bridge',
          'mcp_server_oauth',
        ], TRUE);
      },
    );
    $readiness = new McpGovernanceReadiness(
      $this->container->get('config.factory'),
      $this->container->get('entity_type.manager'),
      $modules,
      $this->container->get('mcp_sentinel.policy_resolver'),
      $this->container->get('mcp_sentinel.oauth_context'),
      $this->container->get('audit_chain.logger'),
    );
    $this->container->set('mcp_sentinel.governance_readiness', $readiness);
  }

  /**
   * Deletes every mcp_policy_profile config entity.
   */
  private function deleteAllProfiles(): void {
    $storage = $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile');
    $profiles = $storage->loadMultiple();
    if ($profiles) {
      $storage->delete($profiles);
    }
  }

  /**
   * Labels above the floor with a role-bound profile lacking ceilings warn.
   *
   * The shipped role-less default profile never trips this: binding a profile
   * to agent roles is what makes it production-oriented. Setting ceilings on
   * that profile clears the warning; an empty map never warns.
   */
  public function testClassificationWithoutCeilingsWarns(): void {
    // Shipped state: the map labels identity types restricted, but the only
    // profile is the role-less default -> no warning.
    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_classification_ceilings', $requirements);

    // A role-bound profile without ceilings -> warning.
    McpPolicyProfile::create([
      'id' => 'agents',
      'label' => 'Agents',
      'roles' => ['mcp_api'],
    ])->save();
    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_classification_ceilings', $requirements);
    $this->assertSame(REQUIREMENT_WARNING, $requirements['mcp_sentinel_classification_ceilings']['severity']);
    $this->assertStringContainsString('agents', (string) $requirements['mcp_sentinel_classification_ceilings']['value']);

    // Ceilings on that profile clear it.
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.agents')
      ->set('egress_ceilings', ['jsonapi' => 'internal'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $this->assertArrayNotHasKey('mcp_sentinel_classification_ceilings', mcp_sentinel_requirements('runtime'));

    // A disabled role-bound profile without ceilings does not count.
    McpPolicyProfile::create([
      'id' => 'retired',
      'label' => 'Retired',
      'roles' => ['mcp_api'],
      'status' => FALSE,
    ])->save();
    $this->assertArrayNotHasKey('mcp_sentinel_classification_ceilings', mcp_sentinel_requirements('runtime'));

    // With nothing labelled above the floor there is nothing to warn about.
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.agents')
      ->set('egress_ceilings', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $this->config('mcp_sentinel.settings')->set('classification_map', [])->save();
    $this->assertArrayNotHasKey('mcp_sentinel_classification_ceilings', mcp_sentinel_requirements('runtime'));
  }

}
