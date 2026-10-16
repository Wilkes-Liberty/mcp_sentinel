<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Context refuses a role-fallback call that has no principal.
 *
 * JSON:API and GraphQL HTTP keep role fallback as the local-dev path.
 * The principal gate on those seams runs only for a validated bearer.
 * The kernel audit fixture seals one; these tests drop it first.
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
   * Role-fallback JSON:API and GraphQL HTTP do not require a token principal.
   */
  public function testHttpRoleFallbackDoesNotRequirePrincipal(): void {
    $this->switchToGovernedUser();
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    foreach (['/jsonapi/node/article', '/graphql'] as $path) {
      $this->dropStampedPrincipal();
      $before = $this->deniedAccessCount();
      $subscriber->onRequest($this->requestEvent($path));
      $this->assertSame($before, $this->deniedAccessCount(), $path);
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
