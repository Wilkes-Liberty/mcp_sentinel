<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\simple_oauth\Authentication\TokenAuthUserInterface;
use Drupal\simple_oauth\Entity\Oauth2TokenInterface;
use Drupal\simple_oauth\Oauth2ScopeInterface;
use Drupal\simple_oauth\Plugin\Field\FieldType\Oauth2ScopeReferenceItemListInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests OAuth agent-channel detection via McpOauthContext.
 *
 * PHPUnit mock objects are used for the token/scope/consumer chain so that
 * return-type declarations are satisfied without performing a real OAuth grant.
 * The mock method names match the real simple_oauth / consumers API
 * (verified 2026-05-30):
 *   - token scopes: $token->get('scopes')->getScopes(), each ->getName()
 *   - consumer client id: $consumer->getClientId() (ConsumerInterface)
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpOauthContext
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpOauthContextTest extends KernelTestBase {

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
    'options',
    'image',
    'path_alias',
    'serialization',
    'jsonapi',
    'tool',
    'key',
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
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * A non-OAuth (cookie-session) account is not on the agent channel.
   *
   * @covers ::isAgentChannel
   * @covers ::scopes
   * @covers ::clientId
   */
  public function testNonOauthAccountNotOnChannel(): void {
    // The default kernel current_user is a plain AccountProxy — not a
    // TokenAuthUser — so the service must return safe zero values.
    $ctx = $this->container->get('mcp_sentinel.oauth_context');
    $this->assertFalse($ctx->isAgentChannel());
    $this->assertSame([], $ctx->scopes());
    $this->assertNull($ctx->clientId());
  }

  /**
   * A token user whose scopes include an agent scope IS on the channel.
   *
   * @covers ::isAgentChannel
   * @covers ::scopes
   * @covers ::clientId
   */
  public function testTokenUserWithAgentScopeIsOnChannel(): void {
    $proxy = $this->createMock(AccountProxyInterface::class);
    $tokenUser = $this->createMock(TokenAuthUserInterface::class);
    $proxy->method('getAccount')->willReturn($tokenUser);

    $scope = $this->createMock(Oauth2ScopeInterface::class);
    $scope->method('getName')->willReturn('mcp_write');

    $scopesField = $this->createMock(Oauth2ScopeReferenceItemListInterface::class);
    $scopesField->method('getScopes')->willReturn([$scope]);

    $token = $this->createMock(Oauth2TokenInterface::class);
    $token->method('get')->with('scopes')->willReturn($scopesField);

    $consumer = $this->createMock(Consumer::class);
    $consumer->method('getClientId')->willReturn('mcp-agent');

    $tokenUser->method('getToken')->willReturn($token);
    $tokenUser->method('getConsumer')->willReturn($consumer);

    $ctx = new McpOauthContext($proxy, $this->container->get('config.factory'));
    $this->assertSame(['mcp_write'], $ctx->scopes());
    $this->assertSame('mcp-agent', $ctx->clientId());
    $this->assertTrue($ctx->isAgentChannel());
  }

  /**
   * A token user with no agent scopes and no designated client is not governed.
   *
   * @covers ::isAgentChannel
   */
  public function testTokenUserWithNoAgentScopeIsNotOnChannel(): void {
    $proxy = $this->createMock(AccountProxyInterface::class);
    $tokenUser = $this->createMock(TokenAuthUserInterface::class);
    $proxy->method('getAccount')->willReturn($tokenUser);

    $scope = $this->createMock(Oauth2ScopeInterface::class);
    $scope->method('getName')->willReturn('some:other');

    $scopesField = $this->createMock(Oauth2ScopeReferenceItemListInterface::class);
    $scopesField->method('getScopes')->willReturn([$scope]);

    $token = $this->createMock(Oauth2TokenInterface::class);
    $token->method('get')->with('scopes')->willReturn($scopesField);

    $consumer = $this->createMock(Consumer::class);
    $consumer->method('getClientId')->willReturn('some-other-client');

    $tokenUser->method('getToken')->willReturn($token);
    $tokenUser->method('getConsumer')->willReturn($consumer);

    $ctx = new McpOauthContext($proxy, $this->container->get('config.factory'));
    $this->assertSame(['some:other'], $ctx->scopes());
    $this->assertSame('some-other-client', $ctx->clientId());
    $this->assertFalse($ctx->isAgentChannel());
  }

  /**
   * A designated client ID alone is enough to put a token on the agent channel.
   *
   * The token may carry scopes unrelated to MCP, but when its consumer is in
   * the agent_oauth_clients allowlist the request is still governed.
   *
   * @covers ::isAgentChannel
   */
  public function testDesignatedClientIdAloneIsOnChannel(): void {
    // Register a specific client as a designated agent client.
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', ['my-designated-client'])
      ->save();

    $proxy = $this->createMock(AccountProxyInterface::class);
    $tokenUser = $this->createMock(TokenAuthUserInterface::class);
    $proxy->method('getAccount')->willReturn($tokenUser);

    // Scope does NOT match any agent scope.
    $scope = $this->createMock(Oauth2ScopeInterface::class);
    $scope->method('getName')->willReturn('some:unrelated');

    $scopesField = $this->createMock(Oauth2ScopeReferenceItemListInterface::class);
    $scopesField->method('getScopes')->willReturn([$scope]);

    $token = $this->createMock(Oauth2TokenInterface::class);
    $token->method('get')->with('scopes')->willReturn($scopesField);

    $consumer = $this->createMock(Consumer::class);
    $consumer->method('getClientId')->willReturn('my-designated-client');

    $tokenUser->method('getToken')->willReturn($token);
    $tokenUser->method('getConsumer')->willReturn($consumer);

    $ctx = new McpOauthContext($proxy, $this->container->get('config.factory'));
    $this->assertTrue($ctx->isAgentChannel());
  }

  /**
   * The verifier's channel flag governs, and clearing it restores the miss.
   *
   * @covers ::setVerificationChannel
   * @covers ::isAgentChannel
   */
  public function testVerificationChannelIsRequestScoped(): void {
    $ctx = $this->container->get('mcp_sentinel.oauth_context');
    $this->assertFalse($ctx->isAgentChannel());
    $ctx->setVerificationChannel(TRUE);
    $this->assertTrue($ctx->isAgentChannel());
    $ctx->setVerificationChannel(FALSE);
    $this->assertFalse($ctx->isAgentChannel());
  }

}
