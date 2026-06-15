<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
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
 * Approach mirrors McpUpdateHookChainTest: the .install file is loaded directly
 * and the hook function is invoked, simulating each config end-state in turn.
 *
 * @group mcp_sentinel
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

}
