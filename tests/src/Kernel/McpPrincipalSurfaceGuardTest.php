<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\mcp_sentinel\EventSubscriber\McpJsonApiPageLimitSubscriber;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Ready-path JSON:API, GraphQL HTTP, and context require a principal.
 *
 * Role fallback still makes those surfaces applicable under
 * PHPUnit when the request is not proxied. The kernel audit
 * fixture seals one; these tests drop it first.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpPrincipalSurfaceGuardTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
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
    $this->installSchema('system', ['sequences']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * Ready-path JSON:API and GraphQL HTTP require a principal.
   *
   * Matches GraphQL operations and /drupal-mcp/context. Role fallback
   * still makes the surface applicable under PHPUnit when the
   * request is not proxied.
   */
  public function testHttpRoleFallbackRequiresPrincipal(): void {
    $this->switchToGovernedUser();
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    foreach (['/jsonapi/node/article', '/graphql'] as $path) {
      $this->dropStampedPrincipal();
      $before = $this->deniedAccessCount();
      try {
        $subscriber->onRequest($this->requestEvent($path));
        $this->fail($path . ' must refuse a ready call without a principal.');
      }
      catch (AccessDeniedHttpException $e) {
        $this->assertNotSame('', $e->getMessage());
      }
      $this->assertSame($before + 1, $this->deniedAccessCount(), $path);
    }
  }

  /**
   * The context endpoint returns a generic 403 and audits the rule.
   */
  public function testContextDeniesWithoutPrincipal(): void {
    $this->switchToGovernedUser();
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(403, $response->getStatusCode());
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('MCP access is denied.', $payload['error'] ?? NULL);
    $this->assertArrayNotHasKey('reason', $payload);
    $this->assertArrayNotHasKey('rule', $payload);
    $this->assertStringNotContainsString('missing_principal', (string) $response->getContent());
    $this->assertStringNotContainsString('[rule:', (string) $response->getContent());
    $this->assertStringContainsString('private', (string) $response->headers->get('Cache-Control'));
    $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $this->assertSame('context', $this->lastDenialMetadata()['tool']);
    $this->assertSame('missing_principal', $this->lastDenialMetadata()['reason']);
    $this->assertStringContainsString('[rule:', (string) ($this->lastDenialMetadata()['explain'] ?? ''));
  }

  /**
   * A NULL dispatcher is audited as missing_dispatcher on context and HTTP.
   *
   * Role fallback still makes the surface ready. The fail-closed
   * reason must not be missing_principal: that tells operators to
   * mint a token when the container was not rebuilt. The controller
   * property is readonly; the NULL path is reached through a
   * container whose dispatcher service resolves to NULL.
   */
  public function testDeniesWhenDispatcherMissing(): void {
    $this->switchToGovernedUser();
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();

    $container = $this->containerWithNullDispatcher();
    $response = McpContextController::create($container)->context();
    $this->assertSame(403, $response->getStatusCode());
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('MCP access is denied.', $payload['error'] ?? NULL);
    $this->assertArrayNotHasKey('reason', $payload);
    $this->assertStringNotContainsString(
      'missing_dispatcher',
      (string) $response->getContent(),
    );
    $this->assertStringNotContainsString(
      'missing_principal',
      (string) $response->getContent(),
    );
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_DISPATCHER,
      $meta['reason'],
    );
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_DISPATCHER,
      $meta['rule'],
    );
    $this->assertStringContainsString(
      'dispatcher',
      (string) ($meta['explain'] ?? ''),
    );

    $subscriber = new McpJsonApiPageLimitSubscriber(
      $this->container->get('mcp_sentinel.access_checker'),
      $this->container->get('mcp_sentinel.governance_readiness'),
      $this->container->get('current_user'),
      $this->container->get('mcp_sentinel.rate_limiter'),
      $this->container->get('mcp_sentinel.read_budgets'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->has('mcp_sentinel.classification')
        ? $this->container->get('mcp_sentinel.classification')
        : NULL,
      NULL,
      $this->container->get('mcp_sentinel.deny_explainer'),
    );
    foreach (['/jsonapi/node/article', '/graphql'] as $path) {
      $event = $this->requestEvent($path);
      // refuse() names the surface from the current request path.
      $this->pushRequestKeepingSession($event->getRequest());
      $beforePath = $this->deniedAccessCount();
      try {
        $subscriber->onRequest($event);
        $this->fail($path . ' must refuse when the dispatcher is missing.');
      }
      catch (AccessDeniedHttpException $e) {
        $this->assertSame('MCP access is denied.', $e->getMessage());
        $this->assertStringNotContainsString(
          'missing_dispatcher',
          $e->getMessage(),
        );
        $this->assertStringNotContainsString(
          'missing_principal',
          $e->getMessage(),
        );
      }
      $this->assertSame($beforePath + 1, $this->deniedAccessCount(), $path);
      $pathMeta = $this->lastDenialMetadata();
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_DISPATCHER,
        $pathMeta['reason'],
        $path,
      );
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_DISPATCHER,
        $pathMeta['rule'],
        $path,
      );
    }
  }

  /**
   * Container whose principal-context dispatcher service is NULL.
   *
   * Models a cached container that was not rebuilt. has() stays
   * TRUE so create() takes the get() branch and receives NULL.
   */
  private function containerWithNullDispatcher(): ContainerInterface {
    $inner = $this->container;
    $container = $this->createMock(ContainerInterface::class);
    $container->method('has')->willReturnCallback(
      static fn (string $id): bool => $inner->has($id),
    );
    $container->method('get')->willReturnCallback(
      static function (string $id) use ($inner): ?object {
        if ($id === 'mcp_sentinel.principal_context_dispatcher') {
          return NULL;
        }
        return $inner->get($id);
      },
    );
    return $container;
  }

  /**
   * A missing audit table still returns the JSON denial, not a 500.
   */
  public function testContextDenialSurvivesAuditOutage(): void {
    $this->switchToGovernedUser();
    $this->dropStampedPrincipal();
    $this->container->get('database')->schema()->dropTable('audit_chain_log');
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(403, $response->getStatusCode());
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('MCP access is denied.', $payload['error'] ?? NULL);
    $this->assertArrayNotHasKey('reason', $payload);
    $this->assertStringNotContainsString('missing_principal', (string) $response->getContent());
    $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
  }

  /**
   * Role fallback makes the surface ready without supplying a principal.
   */
  private function switchToGovernedUser(): void {
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Main request event for a governed HTTP path.
   */
  private function requestEvent(string $path): RequestEvent {
    return new RequestEvent(
      $this->container->get('http_kernel'),
      Request::create($path),
      HttpKernelInterface::MAIN_REQUEST,
    );
  }

  /**
   * Counts denied_access rows written during this test.
   */
  private function deniedAccessCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Decodes the latest denied_access metadata.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  private function lastDenialMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
  }

}
