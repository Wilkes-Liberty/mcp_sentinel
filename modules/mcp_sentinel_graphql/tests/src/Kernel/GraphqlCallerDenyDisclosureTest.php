<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Kernel;

use Drupal\graphql\Event\OperationEvent;
use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedEntryPointTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use GraphQL\Error\Error;
use GraphQL\Server\OperationParams;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * GraphQL Errors hide the [rule:] explainer (DEV-966).
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_graphql
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_graphql')]
#[RunTestsInSeparateProcesses]
final class GraphqlCallerDenyDisclosureTest extends KernelTestBase {

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
   * A missing principal GraphQL Error is generic; the audit row names the rule.
   */
  public function testGraphqlHidesMissingPrincipalRule(): void {
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    try {
      $this->subscriber()->onOperation($this->makeEvent('query'));
      $this->fail('GraphQL must refuse a call with no principal.');
    }
    catch (Error $e) {
      $this->assertSame('MCP access is denied.', $e->getMessage());
      $this->assertStringNotContainsString('[rule:', $e->getMessage());
      $this->assertStringNotContainsString(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->getMessage(),
      );
    }
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame('graphql', $meta['tool']);
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      $meta['reason'],
    );
    $this->assertArrayHasKey('explain', $meta);
    $this->assertStringContainsString('[rule:', (string) $meta['explain']);
    $this->assertStringContainsString(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      (string) $meta['explain'],
    );
  }

  /**
   * A missing tenant claim GraphQL Error hides the rule id.
   */
  public function testGraphqlHidesMissingTenantRule(): void {
    $this->pushEntryPointRequest(
      [
        'iss' => self::ENTRY_POINT_ISS,
        'sub' => 'surface-agent',
        'azp' => 'surface-client',
        'scopes' => ['mcp_read'],
      ],
      '/graphql',
    );
    $before = $this->deniedAccessCount();
    try {
      $this->subscriber()->onOperation($this->makeEvent('query'));
      $this->fail('GraphQL must refuse a network call with no tenant claim.');
    }
    catch (Error $e) {
      $this->assertSame('MCP access is denied.', $e->getMessage());
      $this->assertStringNotContainsString('[rule:', $e->getMessage());
      $this->assertStringNotContainsString(
        McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
        $e->getMessage(),
      );
      $this->assertStringNotContainsString('tenant claim', $e->getMessage());
    }
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
      $meta['reason'],
    );
    $this->assertArrayHasKey('explain', $meta);
    $this->assertStringContainsString('[rule:', (string) $meta['explain']);
    $this->assertStringContainsString(
      McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
      (string) $meta['explain'],
    );
  }

  /**
   * Subscriber from real container services.
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
   * Minimal OperationEvent wrapping a mocked ResolveContext.
   */
  private function makeEvent(string $type): OperationEvent {
    $params = OperationParams::create(['query' => '{ __typename }']);
    $context = $this->createMock(ResolveContext::class);
    $context->method('getType')->willReturn($type);
    $context->method('getOperation')->willReturn($params);
    $context->method('mergeCacheMaxAge')->willReturnSelf();
    return new OperationEvent($context);
  }

}
