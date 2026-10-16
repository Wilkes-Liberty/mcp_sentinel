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
use GraphQL\Error\DebugFlag;
use GraphQL\Error\Error;
use GraphQL\Error\FormattedError;
use GraphQL\Server\OperationParams;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

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
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    $stack = $this->container->get('request_stack');
    while ($stack->getCurrentRequest() !== NULL
      && $stack->getCurrentRequest() !== $stack->getMainRequest()) {
      $stack->pop();
    }
    parent::tearDown();
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
      $this->assertGraphqlErrorHidesPrevious($e);
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
      $this->assertGraphqlErrorHidesPrevious($e);
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
   * GraphQL HTTP 429 hides read_budget_exceeded; the status is the deny class.
   */
  public function testGraphqlHttpSeamHidesReadBudget(): void {
    $this->config('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['requests' => 1, 'request_window' => 60])
      ->save();
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $kernel = $this->container->get('http_kernel');
    $subscriber->onRequest($this->graphqlRequestEvent($kernel));
    try {
      $subscriber->onRequest($this->graphqlRequestEvent($kernel));
      $this->fail('GraphQL must refuse over the request budget.');
    }
    catch (TooManyRequestsHttpException $e) {
      $this->assertSame(429, $e->getStatusCode());
      $this->assertSame('MCP access is denied.', $e->getMessage());
      $this->assertStringNotContainsString('read_budget_exceeded', $e->getMessage());
      $this->assertStringNotContainsString('[rule:', $e->getMessage());
    }
  }

  /**
   * GraphQL HTTP 413 hides response_size_cap_exceeded and the byte counts.
   */
  public function testGraphqlHttpSeamHidesResponseSizeCap(): void {
    $this->config('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['bytes' => 10])
      ->save();
    $subscriber = $this->container->get('mcp_sentinel.governed_response_subscriber');
    $request = Request::create('/graphql', 'POST');
    $this->container->get('request_stack')->push($request);
    $event = new ResponseEvent(
      $this->container->get('http_kernel'),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      new Response(str_repeat('y', 11), 200),
    );
    $subscriber->onResponse($event);
    $this->assertSame(413, $event->getResponse()->getStatusCode());
    $body = (string) $event->getResponse()->getContent();
    $this->assertStringContainsString('MCP access is denied.', $body);
    $this->assertStringNotContainsString('response_size_cap_exceeded', $body);
    $this->assertStringNotContainsString('[rule:', $body);
    $this->assertStringNotContainsString('11 bytes', $body);
    $this->assertDoesNotMatchRegularExpression('/\b10\b/', $body);
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

  /**
   * Main-request event for a governed GraphQL POST.
   */
  private function graphqlRequestEvent(HttpKernelInterface $kernel): RequestEvent {
    $request = Request::create('/graphql', 'POST');
    $this->container->get('request_stack')->push($request);
    return new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
  }

  /**
   * GraphQL Errors must not carry a previous exception even under debug.
   */
  private function assertGraphqlErrorHidesPrevious(Error $e): void {
    $this->assertNull($e->getPrevious());
    $formatted = FormattedError::createFromException(
      $e,
      DebugFlag::INCLUDE_DEBUG_MESSAGE | DebugFlag::INCLUDE_TRACE,
    );
    $encoded = (string) json_encode($formatted);
    $this->assertStringNotContainsString('McpPrincipalContextDeniedException', $encoded);
    $this->assertStringNotContainsString('missing_principal', $encoded);
    $this->assertStringNotContainsString('missing_tenant_claim', $encoded);
    $this->assertStringNotContainsString('[rule:', $encoded);
  }

}
