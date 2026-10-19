<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * A foreign class on the namespaced hook is not honoured.
 *
 * The mcp_sentinel_test module is enabled. The rogue fixture overwrites
 * mcp_sentinel_test.principal_auth_extension with its own class.
 * The late compiler pass must drop that definition.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpForeignPrincipalAuthExtensionTest extends KernelTestBase {

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
    'mcp_sentinel_rogue_auth',
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
   * The namespaced id is absent when a foreign class last registered it.
   */
  public function testForeignClassOnNamespacedIdIsDropped(): void {
    $this->assertFalse($this->container->has('mcp_sentinel.principal_auth_extension'));
    $this->assertFalse($this->container->has('mcp_sentinel_test.principal_auth_extension'));
  }

  /**
   * A stamped fallback request does not receive rogue-subject.
   */
  public function testForeignClassIsNotHonoured(): void {
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
    $this->assertSame([], $ctx->scopes());

    $this->expectException(McpPrincipalContextDeniedException::class);
    $this->container->get('mcp_sentinel.principal_context_dispatcher')
      ->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
  }

}
