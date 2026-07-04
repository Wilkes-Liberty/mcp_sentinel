<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests OAuth-agent-channel governance via McpPolicyResolver.
 *
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpPolicyResolverOauthTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * The agent-channel settings ship with sensible defaults.
   */
  public function testAgentChannelDefaults(): void {
    $config = $this->config('mcp_sentinel.settings');
    // agent_scopes is the set of OAuth scopes recognized as the agent channel.
    // It has included mcp_config since the 1.2.0 config-scope isolation so that
    // dev/admin tier tokens (which carry mcp_config) are still governed, and
    // mcp_config_read since 1.5.0 so a read-only config auditor token (which
    // carries only that scope) is recognized on the agent channel.
    $this->assertSame(
      ['mcp_read', 'mcp_write', 'mcp_config', 'mcp_config_read'],
      $config->get('agent_scopes'),
    );
    $this->assertFalse($config->get('governed_role_fallback'));
  }

  /**
   * A governed ROLE alone does NOT govern when fallback is off and no token.
   *
   * With governed_role_fallback = FALSE and no OAuth token on the request,
   * a user holding the governed role must NOT be governed. This ensures the
   * admin cookie-session UI is ungoverned (the core Phase-2 goal).
   */
  public function testRoleAloneDoesNotGovernWithoutToken(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', FALSE)
      ->save();
    Role::create(['id' => 'mcp_api', 'label' => 'mcp_api'])->save();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    // No OAuth token on this request → not on the agent channel.
    $this->assertFalse(
      $this->container->get('mcp_sentinel.policy_resolver')->isGoverned($account)
    );
  }

  /**
   * With the local-dev fallback ON, a governed role governs even without token.
   *
   * When governed_role_fallback = TRUE, the Phase-1 role-based check is
   * preserved as an explicit opt-in for local development environments.
   */
  public function testRoleFallbackGovernsWhenEnabled(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', TRUE)
      ->save();
    Role::create(['id' => 'mcp_api', 'label' => 'mcp_api'])->save();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->assertTrue(
      $this->container->get('mcp_sentinel.policy_resolver')->isGoverned($account)
    );
  }

  /**
   * Cookie-session admin UI: resolve() returns NULL, even for admin roles.
   *
   * With governed_role_fallback = FALSE and no OAuth token, resolve() MUST
   * return NULL for any account regardless of role. This is the core guarantee
   * that the admin Drupal UI is never governed by MCP Sentinel.
   */
  public function testCookieSessionAdminUiIsUngoverned(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['administrator'])
      ->set('governed_role_fallback', FALSE)
      ->save();
    Role::create(['id' => 'administrator', 'label' => 'Administrator'])->save();
    $account = $this->createUser([], NULL, TRUE);
    // No OAuth token — the account must not be governed.
    $resolver = $this->container->get('mcp_sentinel.policy_resolver');
    $this->assertFalse($resolver->isGoverned($account));
    $this->assertNull($resolver->resolve($account));
  }

  /**
   * On the OAuth agent channel, a governed role resolves to the role profile.
   *
   * Stubs mcp_sentinel.oauth_context by constructing a partial mock whose
   * isAgentChannel() returns TRUE. McpPolicyResolver is then built manually
   * with the stub so that container-cached services do not interfere with
   * the channel detection under test. This proves channel-triggers +
   * role-selects without a real OAuth grant.
   */
  public function testAgentChannelTriggersPlusRoleSelectsProfile(): void {
    // Set up a role and a role-specific profile.
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', FALSE)
      ->save();
    Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    McpPolicyProfile::create([
      'id' => 'agent_profile',
      'label' => 'Agent profile',
      'roles' => ['mcp_api'],
      'weight' => 10,
      'allow_write' => TRUE,
      'allow_delete' => FALSE,
    ])->save();

    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);

    // Stub: isAgentChannel() = TRUE, other methods return safe defaults.
    $oauthStub = $this->createMock(McpOauthContext::class);
    $oauthStub->method('isAgentChannel')->willReturn(TRUE);
    $oauthStub->method('scopes')->willReturn(['mcp_write']);
    $oauthStub->method('clientId')->willReturn('mcp-agent-test');

    // Construct the resolver with the stub so that container-cached real
    // services cannot interfere with the channel detection under test.
    $resolver = new McpPolicyResolver(
      $this->container->get('config.factory'),
      $this->container->get('entity_type.manager'),
      $this->container->get('current_user'),
      $oauthStub,
    );

    // Channel triggers → governed.
    $this->assertTrue($resolver->isGoverned($account));
    // Role selects the profile.
    $profile = $resolver->resolve($account);
    $this->assertNotNull($profile);
    $this->assertSame('agent_profile', $profile->id());
    $this->assertTrue($profile->allowsWrite());
    $this->assertFalse($profile->allowsDelete());
  }

  /**
   * The governed_role_fallback setting is irrelevant on the agent channel.
   *
   * Even when governed_role_fallback = FALSE, an OAuth-channel request is
   * governed. The fallback setting controls only the cookie-session path.
   */
  public function testAgentChannelGovernsRegardlessOfRoleFallback(): void {
    // Explicitly disable the role fallback.
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', FALSE)
      ->save();
    Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);

    // Stub: channel is active regardless of the fallback setting.
    $oauthStub = $this->createMock(McpOauthContext::class);
    $oauthStub->method('isAgentChannel')->willReturn(TRUE);

    $resolver = new McpPolicyResolver(
      $this->container->get('config.factory'),
      $this->container->get('entity_type.manager'),
      $this->container->get('current_user'),
      $oauthStub,
    );

    // Governed via the channel even though role_fallback is off.
    $this->assertTrue($resolver->isGoverned($account));
    // resolve() returns non-NULL (falls back to 'default' profile).
    $this->assertNotNull($resolver->resolve($account));
  }

}
