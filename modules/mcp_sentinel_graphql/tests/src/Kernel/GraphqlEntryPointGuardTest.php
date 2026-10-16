<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Kernel;

use Drupal\graphql\Event\OperationEvent;
use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedEntryPointTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use GraphQL\Error\Error;
use GraphQL\Server\OperationParams;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * GraphQL requirePrincipal refuses at assertDispatchAllowed (DEV-927).
 *
 * Deny-path tests fail when McpPrincipalContextGuard::disableForTest()
 * is injected and pass when the guard is on.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber
 * @group mcp_sentinel
 * @group mcp_sentinel_graphql
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_graphql')]
#[RunTestsInSeparateProcesses]
final class GraphqlEntryPointGuardTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedEntryPointTestTrait;
  use UserCreationTrait;

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
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel']);
    $this->switchToGovernedUser();
  }

  /**
   * A role-fallback operation without a principal is refused and audited.
   *
   * @covers ::onOperation
   */
  public function testDeniesWithoutPrincipal(): void {
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('query');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
  }

  /**
   * A bearer that cannot compose a principal key is refused.
   *
   * @covers ::onOperation
   */
  public function testDeniesUnverifiedPrincipal(): void {
    $this->pushEntryPointRequest($this->unverifiedEntryPointClaims(), '/graphql');
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('query');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
    $this->assertArrayHasKey('principal_unverified', $this->lastDenialMetadata());
  }

  /**
   * A killed principal is refused with a generic deny (DEV-846).
   *
   * @covers ::onOperation
   */
  public function testDeniesKilledPrincipal(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims(), '/graphql');
    $this->killVerifiedEntryPointPrincipal();
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('query');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpKillSwitch::DENY_REASON,
      TRUE,
    );
  }

  /**
   * A mutation is refused when the token only grants mcp_read.
   *
   * @covers ::onOperation
   */
  public function testDeniesScopeOutsideToken(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_read']),
      '/graphql',
    );
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('mutation');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * The urn:mcp-sentinel:sealed-token issuer is refused (DEV-843).
   *
   * @covers ::onOperation
   */
  public function testDeniesSealedTokenIssuer(): void {
    $this->pushEntryPointRequest(
      $this->sealedTokenEntryPointClaims(),
      '/graphql',
      'POST',
      TRUE,
    );
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('query');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpPrincipalContextDeniedException::NON_IDP_ISSUER,
      TRUE,
      McpSealedTokenManager::ISSUER . '|c2b8c8d6-0000-4000-8000-000000000001|surface-client',
    );
  }

  /**
   * A Paladin token that lists no scopes is refused.
   *
   * @covers ::onOperation
   */
  public function testDeniesPaladinEmptyScopes(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims([]),
      '/graphql',
    );
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('query');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * A mutation is admitted when the token grants mcp_write.
   *
   * @covers ::onOperation
   */
  public function testAllowsMutationWithMcpWrite(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims(), '/graphql');
    $before = $this->deniedAccessCount();
    $this->subscriber()->onOperation($this->makeEvent('mutation'));
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * A subscription requires mcp_read.
   *
   * @covers ::onOperation
   */
  public function testDeniesSubscriptionWithoutMcpRead(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_write']),
      '/graphql',
    );
    $before = $this->deniedAccessCount();
    $this->assertGraphqlDenied('subscription');
    $this->assertSurfaceDenialRow(
      $before,
      'graphql',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * A subscription is admitted when the token grants mcp_read.
   *
   * @covers ::onOperation
   */
  public function testAllowsSubscriptionWithMcpRead(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims(), '/graphql');
    $before = $this->deniedAccessCount();
    $this->subscriber()->onOperation($this->makeEvent('subscription'));
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * Unknown GraphQL operation types are refused.
   *
   * @covers ::onOperation
   */
  public function testDeniesUnknownOperationType(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims(), '/graphql');
    $before = $this->deniedAccessCount();
    try {
      $this->subscriber()->onOperation($this->makeEvent('unknown'));
      $this->fail('An unknown GraphQL operation type must be refused.');
    }
    catch (Error $e) {
      $this->assertStringContainsString('not permitted', $e->getMessage());
    }
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * A verified Paladin bearer that grants mcp_read may run a query.
   *
   * @covers ::onOperation
   */
  public function testAllowsVerifiedPrincipal(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims(), '/graphql');
    $before = $this->deniedAccessCount();
    $this->subscriber()->onOperation($this->makeEvent('query'));
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * Asserts onOperation throws a GraphQL Error.
   */
  private function assertGraphqlDenied(string $type): void {
    try {
      $this->subscriber()->onOperation($this->makeEvent($type));
      $this->fail('GraphQL must refuse this governed operation.');
    }
    catch (Error $e) {
      $this->assertNotSame('', $e->getMessage());
    }
  }

  /**
   * Returns a fresh subscriber from real container services.
   */
  private function subscriber(): GraphqlGovernanceSubscriber {
    return new GraphqlGovernanceSubscriber(
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.governance_readiness'),
      $this->container->get('current_user'),
      $this->container->get('mcp_sentinel.access_checker'),
      NULL,
      $this->container->get('request_stack'),
      $this->container->get('mcp_sentinel.principal_context_dispatcher'),
    );
  }

  /**
   * Builds a minimal OperationEvent wrapping a mocked ResolveContext.
   */
  private function makeEvent(string $type): OperationEvent {
    $context = $this->createMock(ResolveContext::class);
    $context->method('getType')->willReturn($type);
    $context->method('getOperation')->willReturn(
      OperationParams::create(['query' => '{ __typename }']),
    );
    $context->method('mergeCacheMaxAge')->willReturnSelf();
    return new OperationEvent($context);
  }

}
