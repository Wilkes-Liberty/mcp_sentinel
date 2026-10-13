<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpPrincipalKey;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Shared principal-key service matches the frozen context.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalKey
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalKey::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalKeyTest extends UnitTestCase {

  /**
   * The service returns iss|sub|azp for a token without act.
   *
   * @covers ::formatPrincipal
   * @covers ::formatHuman
   */
  public function testNonDelegatedToken(): void {
    $ctx = $this->context([]);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-client',
      McpPrincipalKey::formatPrincipal($ctx),
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      McpPrincipalKey::formatHuman($ctx),
    );
    $this->assertSame(
      $ctx->principalKey(),
      McpPrincipalKey::formatPrincipal($ctx),
    );
    $this->assertSame(
      $ctx->humanKey(),
      McpPrincipalKey::formatHuman($ctx),
    );
  }

  /**
   * The service uses the immediate act.sub when a chain is present.
   *
   * @covers ::formatPrincipal
   * @covers ::formatHuman
   */
  public function testDelegatedToken(): void {
    $ctx = $this->context(['agent-1', 'agent-2']);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-1',
      McpPrincipalKey::formatPrincipal($ctx),
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      McpPrincipalKey::formatHuman($ctx),
    );
    $this->assertSame(
      $ctx->principalKey(),
      McpPrincipalKey::formatPrincipal($ctx),
    );
    $this->assertSame(
      $ctx->humanKey(),
      McpPrincipalKey::formatHuman($ctx),
    );
  }

  /**
   * Builds a frozen context.
   *
   * @param list<string> $actChain
   *   Delegation chain, outermost first.
   */
  private function context(array $actChain): McpPrincipalContext {
    return new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-client',
      'agent-client',
      ['mcp_read'],
      'tenant-a',
      $actChain,
      TRUE,
    );
  }

}
