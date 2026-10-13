<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Frozen principal + tenant context and reserved-key rejection.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpPrincipalContext
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContext::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextTest extends UnitTestCase {

  /**
   * Reserved identity keys are a single constant list.
   *
   * @covers ::reservedKeysIn
   */
  public function testReservedIdentityKeysAreThePublishedList(): void {
    $this->assertContains('user', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('tenant', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('on_behalf_of', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertSame(
      ['user', 'Tenant'],
      McpPrincipalContext::reservedKeysIn([
        'query' => 'ok',
        'Tenant' => 'evil',
        'user' => '2',
      ]),
    );
    $this->assertSame([], McpPrincipalContext::reservedKeysIn([
      'query' => 'ok',
      'note' => 'fine',
    ]));
  }

  /**
   * A tool cannot mutate the frozen context.
   */
  public function testContextIsImmutable(): void {
    $ctx = new McpPrincipalContext(
      'human-1',
      'agent-client',
      'agent-client',
      ['mcp_read'],
      'tenant-a',
      ['agent-1'],
      TRUE,
    );
    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $ctx->tenant = 'tenant-b';
  }

}
