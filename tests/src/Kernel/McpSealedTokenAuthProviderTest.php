<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use ColinODell\PsrTestLogger\TestLogger;
use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Collector init must not build the sealed-token graph.
 *
 * Drupal constructs every tagged authentication provider when the
 * authentication collector is first resolved. A live
 * mcp_sentinel.sealed_token_manager argument therefore built the
 * manager, audit logger, and DLP during collector init, which closed
 * a ServiceCircularReferenceException on authentication_subscriber
 * on downstream sites whose DLP graph reaches that subscriber
 * (DEV-1014).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSealedTokenAuthProvider::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSealedTokenAuthProviderTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

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
    'image',
    'options',
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
   * Resolving the collector does not instantiate manager, audit, or DLP.
   *
   * @covers ::__construct
   * @covers ::applies
   */
  public function testCollectorDoesNotConstructManagerAuditOrDlp(): void {
    $this->rebuildServiceContainer();
    $this->assertHeavyServicesUninitialized();

    $this->container->get('authentication_collector');
    $this->container->get('authentication_subscriber');
    $this->container->get('authentication');

    $this->assertTrue(
      $this->container->initialized('mcp_sentinel.sealed_token_auth'),
      'sealed_token_auth must be constructed with the collector.',
    );
    $this->assertHeavyServicesUninitialized();
    $provider = $this->provider();
    $this->assertHeavyServicesUninitialized();

    $request = Request::create('/jsonapi');
    $this->assertFalse($provider->applies($request));
    $this->assertHeavyServicesUninitialized();
  }

  /**
   * A blank Authorization header does not apply and never authenticates.
   *
   * @covers ::applies
   * @covers ::authenticate
   */
  public function testBlankAuthorizationDoesNotApplyAndDenies(): void {
    $provider = $this->provider();

    $request = Request::create('/jsonapi');
    $this->assertFalse($provider->applies($request));
    $this->assertNull($provider->authenticate($request));

    $empty = Request::create('/jsonapi');
    $empty->headers->set('Authorization', '');
    $this->assertFalse($provider->applies($empty));
    $this->assertNull($provider->authenticate($empty));
  }

  /**
   * A forged mcs1. bearer applies and is denied.
   *
   * @covers ::applies
   * @covers ::authenticate
   */
  public function testForgedMcs1BearerIsDenied(): void {
    $provider = $this->provider();

    $request = Request::create('/jsonapi');
    $request->headers->set(
      'Authorization',
      'Bearer ' . McpSealedTokenManager::PREFIX . 'forged.not.real',
    );
    $this->assertTrue($provider->applies($request));
    $this->assertNull($provider->authenticate($request));
    $this->assertFalse(
      $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
    );
  }

  /**
   * A closure that returns the wrong type never authenticates.
   *
   * @covers ::authenticate
   * @covers ::tokenManager
   */
  public function testWrongClosureTypeNeverAuthenticates(): void {
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->expects($this->never())->method('getStorage');
    $spy = new TestLogger();
    $provider = new McpSealedTokenAuthProvider(
      static fn () => new \stdClass(),
      $entityTypeManager,
      static fn () => $spy,
    );
    $token = McpSealedTokenManager::PREFIX . 'x';
    $request = Request::create('/jsonapi');
    $request->headers->set('Authorization', 'Bearer ' . $token);

    try {
      $account = $provider->authenticate($request);
    }
    catch (\LogicException $exception) {
      $this->assertStringContainsString(
        'McpSealedTokenManager',
        $exception->getMessage(),
      );
      $this->assertFalse(
        $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
      );
      $this->assertCriticalResolutionLog(
        $spy,
        \LogicException::class,
        $token,
      );
      return;
    }
    $this->fail(
      'Expected LogicException; authenticate() returned '
      . (is_object($account) ? $account::class : gettype($account)),
    );
  }

  /**
   * A closure that throws never authenticates and records the class only.
   *
   * @covers ::authenticate
   * @covers ::tokenManager
   */
  public function testThrowingClosureNeverAuthenticates(): void {
    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->expects($this->never())->method('getStorage');
    $spy = new TestLogger();
    $provider = new McpSealedTokenAuthProvider(
      static fn () => throw new \RuntimeException('boom'),
      $entityTypeManager,
      static fn () => $spy,
    );
    $token = McpSealedTokenManager::PREFIX . 'forged.not.real';
    $request = Request::create('/jsonapi');
    $request->headers->set('Authorization', 'Bearer ' . $token);

    try {
      $account = $provider->authenticate($request);
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('boom', $exception->getMessage());
      $this->assertFalse(
        $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
      );
      $this->assertCriticalResolutionLog(
        $spy,
        \RuntimeException::class,
        $token,
      );
      return;
    }
    $this->fail(
      'Expected RuntimeException; authenticate() returned '
      . (is_object($account) ? $account::class : gettype($account)),
    );
  }

  /**
   * Verify failure does not load a user for forged or revoked tokens.
   *
   * Deleting the `$claims === NULL` guard in authenticate() turns this
   * red: the provider would call getStorage() on a deny.
   *
   * @covers ::authenticate
   */
  public function testVerifyFailureDoesNotLoadUser(): void {
    $this->installTokenTables();
    $owner = $this->createAgentOwner();
    $this->createDesignatedConsumer('mcp-agent-prod', $owner);
    $operator = $this->createOperator();
    $manager = $this->container->get('mcp_sentinel.sealed_token_manager');
    $issued = $manager->mint('mcp-agent-prod', 900, $operator);
    $this->assertTrue($manager->revoke($issued['jti'], $operator));

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->expects($this->never())->method('getStorage');
    $provider = new McpSealedTokenAuthProvider(
      fn () => $manager,
      $entityTypeManager,
      static fn () => new TestLogger(),
    );

    $forged = Request::create('/jsonapi');
    $forged->headers->set(
      'Authorization',
      'Bearer ' . McpSealedTokenManager::PREFIX . 'forged.not.real',
    );
    $this->assertNull($provider->authenticate($forged));
    $this->assertFalse(
      $forged->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
    );

    $revoked = Request::create('/jsonapi');
    $revoked->headers->set('Authorization', 'Bearer ' . $issued['token']);
    $this->assertNull($provider->authenticate($revoked));
    $this->assertFalse(
      $revoked->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
    );
  }

  /**
   * A verified token still stamps the same sealed claims.
   *
   * @covers ::authenticate
   */
  public function testValidTokenWritesSealedClaims(): void {
    $this->installTokenTables();
    $owner = $this->createAgentOwner();
    $this->createDesignatedConsumer('mcp-agent-prod', $owner);
    $issued = $this->container->get('mcp_sentinel.sealed_token_manager')
      ->mint('mcp-agent-prod', 900, $this->createOperator());

    $provider = $this->provider();
    $request = Request::create('/jsonapi');
    $request->headers->set('Authorization', 'Bearer ' . $issued['token']);
    $this->assertTrue($provider->applies($request));

    $account = $provider->authenticate($request);
    $this->assertInstanceOf(UserInterface::class, $account);
    $this->assertSame((int) $owner->id(), (int) $account->id());
    $sealed = $request->attributes->get(McpOauthContext::SEALED_ATTRIBUTE);
    $this->assertIsArray($sealed);
    $this->assertSame('mcp-agent-prod', $sealed['client_id']);
    $this->assertSame($issued['jti'], $sealed['jti']);
    $this->assertSame(McpSealedTokenManager::ISSUER, $sealed['iss']);
    $this->assertSame($owner->uuid(), $sealed['sub']);
    $this->assertSame('mcp-agent-prod', $sealed['azp']);
    $this->assertSame($issued['scopes'], $sealed['scopes']);
    $this->assertArrayNotHasKey('tenant', $sealed);
  }

  /**
   * Rebuilds the container so install-time events do not leave services built.
   */
  private function rebuildServiceContainer(): void {
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();
    \Drupal::setContainer($this->container);
  }

  /**
   * Returns the sealed-token authentication provider.
   */
  private function provider(): McpSealedTokenAuthProvider {
    return $this->container->get('mcp_sentinel.sealed_token_auth');
  }

  /**
   * Asserts the services that closed the auth cycle are still lazy.
   */
  private function assertHeavyServicesUninitialized(): void {
    $this->assertFalse(
      $this->container->initialized('mcp_sentinel.sealed_token_manager'),
      'sealed_token_manager must stay uninitialized until authenticate().',
    );
    $this->assertFalse(
      $this->container->initialized('mcp_sentinel.audit_logger'),
      'audit_logger must stay uninitialized until first use.',
    );
    $this->assertFalse(
      $this->container->initialized('mcp_sentinel.dlp'),
      'dlp must stay uninitialized until first use.',
    );
  }

  /**
   * Asserts a critical mcp_sentinel log names the class and omits the token.
   *
   * @param \ColinODell\PsrTestLogger\TestLogger $logger
   *   Capturing logger.
   * @param string $class
   *   Expected exception class recorded in the log.
   * @param string $token
   *   Bearer that must not appear in the log.
   */
  private function assertCriticalResolutionLog(
    TestLogger $logger,
    string $class,
    string $token,
  ): void {
    $critical = array_values(array_filter(
      $logger->records,
      static fn (array $record): bool => $record['level'] === 'critical',
    ));
    $this->assertNotEmpty(
      $critical,
      'mcp_sentinel channel must record a critical entry.',
    );
    $encoded = json_encode($critical) ?: '';
    $this->assertStringNotContainsString($token, $encoded);
    $this->assertStringNotContainsString('Bearer ', $encoded);
    $haystacks = [];
    foreach ($critical as $record) {
      $haystacks[] = (string) $record['message'];
      $haystacks[] = json_encode($record['context'] ?? []) ?: '';
    }
    $this->assertStringContainsString($class, implode("\n", $haystacks));
  }

  /**
   * Installs the tables a successful mint/verify needs.
   */
  private function installTokenTables(): void {
    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->installConfig(['mcp_sentinel']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_sealed_token']);
  }

  /**
   * Creates the minting operator account.
   */
  private function createOperator(): User {
    $user = User::create([
      'name' => 'mcp-operator',
      'status' => 1,
    ]);
    $user->save();
    return $user;
  }

  /**
   * Creates the designated consumer owner.
   */
  private function createAgentOwner(): User {
    $user = User::create([
      'name' => 'mcp-agent-content',
      'status' => 1,
    ]);
    $user->save();
    return $user;
  }

  /**
   * Creates and designates a Consumer.
   */
  private function createDesignatedConsumer(string $clientId, User $owner): Consumer {
    $consumer = Consumer::create([
      'client_id' => $clientId,
      'label' => $clientId,
      'owner_id' => $owner->id(),
      'user_id' => $owner->id(),
      'secret' => 'not-echoed',
      'confidential' => TRUE,
      'status' => 1,
    ]);
    $consumer->save();
    $this->config('mcp_sentinel.settings')
      ->set('agent_oauth_clients', [$clientId])
      ->save();
    return $consumer;
  }

}
