<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_test\Spoof\NsSpoofPrincipalAuthExtension;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * A Drupal\mcp_sentinel_test\ class from another module path is denied.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpPrincipalAuthNsSpoofTest extends KernelTestBase {

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
    'mcp_sentinel_test',
    'mcp_sentinel_ns_spoof',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * Compile removes the foreign-path spoof; a stamped PATCH stays claimless.
   */
  public function testForeignPathTestNamespaceClassIsRemovedAndDenied(): void {
    $this->assertFalse(
      $this->container->has(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID),
    );
    $request = Request::create('/jsonapi/node/page', 'PATCH');
    $request->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    $stack->push($request);
    $ctx = $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest($request);
    $this->assertSame('', $ctx->subject());
    $this->assertNotSame('rogue-subject', $ctx->subject());
    $this->expectException(McpPrincipalContextDeniedException::class);
    $this->container->get('mcp_sentinel.principal_context_dispatcher')
      ->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
  }

  /**
   * Compile-time removal writes a refused audit row.
   */
  public function testCompileTimeRemovalWritesRefusedAudit(): void {
    $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest(Request::create('/jsonapi/node/page', 'GET'));
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpPrincipalContextFactory::AUDIT_OPERATION)
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $metadata = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $this->assertSame('refused', $metadata['reason'] ?? '');
    $this->assertSame(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      $metadata['service'] ?? '',
    );
    $this->assertSame('mcp_sentinel_ns_spoof', $metadata['provider'] ?? '');
    $this->assertFalse(class_exists(NsSpoofPrincipalAuthExtension::class, FALSE)
      && $this->container->has(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
  }

}
