<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
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
   * Nested maps and case variants are reserved-key hits.
   *
   * @covers ::reservedKeysIn
   */
  public function testReservedKeysCatchNestedAndCaseVariants(): void {
    $this->assertSame(
      ['meta.filters.USER', 'wrap.Tenant_Id', 'On_Behalf_Of'],
      McpPrincipalContext::reservedKeysIn([
        'note' => 'ok',
        'meta' => [
          'filters' => ['USER' => '2'],
        ],
        'wrap' => ['Tenant_Id' => 'evil'],
        'On_Behalf_Of' => 'agent-x',
      ]),
    );
    $this->assertSame(
      ['items.0.tenant', 'items.1.act'],
      McpPrincipalContext::reservedKeysIn([
        'items' => [
          ['tenant' => 'evil'],
          ['act' => ['sub' => 'spoof']],
        ],
      ]),
    );
  }

  /**
   * A non-delegated token keys on iss|sub|azp.
   *
   * @covers ::principalKey
   * @covers ::humanKey
   */
  public function testNonDelegatedTokenPrincipalKeyUsesAzp(): void {
    $ctx = $this->context();
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-client',
      $ctx->principalKey(),
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      $ctx->humanKey(),
    );
  }

  /**
   * A delegated token keys on the immediate act.sub, not azp.
   *
   * @covers ::principalKey
   * @covers ::humanKey
   */
  public function testDelegatedTokenPrincipalKeyUsesImmediateActSub(): void {
    $ctx = $this->context(actChain: ['agent-1', 'agent-2']);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-1',
      $ctx->principalKey(),
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      $ctx->humanKey(),
    );
  }

  /**
   * No act and no azp fails closed (client id is not an actor).
   *
   * @covers ::principalKey
   */
  public function testNonDelegatedTokenWithoutAzpFailsClosed(): void {
    $ctx = $this->context(clientId: 'client-only', azp: '');
    try {
      $ctx->principalKey();
      $this->fail('Missing azp must not produce a principal key.');
    }
    catch (McpPrincipalKeyException $e) {
      $this->assertSame(McpPrincipalKeyException::MISSING_AZP, $e->reasonCode);
    }
  }

  /**
   * A tool cannot mutate the frozen context.
   */
  public function testContextIsImmutable(): void {
    $ctx = $this->context();
    $this->expectException(\Error::class);
    // @phpstan-ignore-next-line
    $ctx->tenant = 'tenant-b';
  }

  /**
   * Builds a frozen context for key tests.
   *
   * @param list<string> $actChain
   *   Delegation chain, outermost first.
   * @param string $clientId
   *   OAuth client id.
   * @param string $azp
   *   Authorized party.
   */
  private function context(
    array $actChain = [],
    string $clientId = 'agent-client',
    string $azp = 'agent-client',
  ): McpPrincipalContext {
    return new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      $clientId,
      $azp,
      ['mcp_read'],
      'tenant-a',
      $actChain,
      TRUE,
    );
  }

}
