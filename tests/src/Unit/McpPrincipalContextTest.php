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
    $this->assertContains('sub', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('iss', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('azp', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('client_id', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('user_id', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('actor', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('scope', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
    $this->assertContains('subject', McpPrincipalContext::RESERVED_IDENTITY_KEYS);
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
      ['items.0.tenant', 'items.1.act', 'items.1.act.sub'],
      McpPrincipalContext::reservedKeysIn([
        'items' => [
          ['tenant' => 'evil'],
          ['act' => ['sub' => 'spoof']],
        ],
      ]),
    );
  }

  /**
   * Matching uses NFKC, strips whitespace/zero-width, folds case.
   *
   * @covers ::normalizeKey
   * @covers ::reservedKeysIn
   */
  public function testReservedKeysNormalizeUnicodeAndZeroWidth(): void {
    $this->assertSame('user', McpPrincipalContext::normalizeKey(' USER '));
    $this->assertSame(
      'user',
      McpPrincipalContext::normalizeKey("us\u{200B}er"),
    );
    $this->assertSame(
      'onbehalfof',
      McpPrincipalContext::normalizeKey('ON-BEHALF-OF'),
    );
    $this->assertSame(
      'user',
      McpPrincipalContext::normalizeKey("us\u{00AD}er"),
    );
    $this->assertSame(
      'user',
      McpPrincipalContext::normalizeKey("us\u{200E}er"),
    );
    $this->assertSame(
      'sub',
      McpPrincipalContext::normalizeKey("sub\u{FE0F}"),
    );
    $this->assertSame(
      [' user ', "us\u{200B}er", 'Ｓｕｂ'],
      McpPrincipalContext::reservedKeysIn([
        ' user ' => '2',
        "us\u{200B}er" => '3',
        'Ｓｕｂ' => '4',
      ]),
    );
  }

  /**
   * Look-alikes fold to the reserved name (Spoofchecker or ASCII skeleton).
   *
   * @covers ::normalizeKey
   */
  public function testLookAlikeReservedKeyIsDetected(): void {
    $cyrillicSub = "\u{0455}ub";
    $this->assertSame(
      [$cyrillicSub],
      McpPrincipalContext::reservedKeysIn([$cyrillicSub => '1']),
    );
  }

  /**
   * A declared-input exception is top-level only, never never-exempt.
   *
   * @covers ::reservedKeysIn
   */
  public function testDeclaredInputExceptionIsTopLevelOnly(): void {
    $this->assertSame(
      [],
      McpPrincipalContext::reservedKeysIn(
        ['subject' => 'Hello'],
        ['subject'],
      ),
    );
    $this->assertSame(
      ['wrap.subject'],
      McpPrincipalContext::reservedKeysIn(
        ['wrap' => ['subject' => 'Hello']],
        ['subject'],
      ),
    );
    $this->assertSame(
      ['sub'],
      McpPrincipalContext::reservedKeysIn(
        ['sub' => 'human-1'],
        ['sub'],
      ),
    );
    $this->assertSame(
      [],
      McpPrincipalContext::reservedKeysIn(
        ['user' => 'display-name'],
        ['user'],
      ),
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
    $keyClaims = [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
    ];
    if ($azp !== '') {
      $keyClaims['azp'] = $azp;
    }
    if ($actChain !== []) {
      $keyClaims['act'] = ['sub' => $actChain[0]];
    }
    return new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      $clientId,
      $azp,
      ['mcp_read'],
      'tenant-a',
      $actChain,
      TRUE,
      $keyClaims,
    );
  }

}
