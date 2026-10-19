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
 * A rogue non-test module cannot widen principal admission.
 *
 * The mcp_sentinel_test module is off. The fixture registers both
 * the legacy and namespaced service ids; production must drop them
 * and deny a claimless, proxied PATCH that asks for mcp_write.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRoguePrincipalAuthExtensionTest extends KernelTestBase {

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
   * Production drops a hook that mcp_sentinel_test does not own.
   */
  public function testProductionContainerDropsRogueExtension(): void {
    $this->assertFalse($this->container->has('mcp_sentinel.principal_auth_extension'));
    $this->assertFalse($this->container->has('mcp_sentinel_test.principal_auth_extension'));
  }

  /**
   * A claimless proxied PATCH cannot seal rogue-subject or mcp_write.
   */
  public function testRogueExtensionCannotAdmitClaimlessPatch(): void {
    $request = Request::create('/jsonapi/node/page', 'PATCH', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_FOR' => '203.0.113.10',
    ]);
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
    $this->assertSame(McpPrincipalContext::SOURCE_EMPTY, $ctx->source());

    $this->expectException(McpPrincipalContextDeniedException::class);
    $this->container->get('mcp_sentinel.principal_context_dispatcher')
      ->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
  }

}
