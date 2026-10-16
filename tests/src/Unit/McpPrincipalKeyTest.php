<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpPrincipalKey;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Shared principal-key service against the language-neutral vectors.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalKey
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalKey::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalKeyTest extends UnitTestCase {

  /**
   * Every shared vector produces the expected keys or error.
   *
   * @param array<string, mixed> $vector
   *   One object from principal-key-vectors.json.
   *
   * @dataProvider vectorProvider
   *
   * @covers ::fromClaims
   */
  #[DataProvider('vectorProvider')]
  public function testSharedVector(array $vector): void {
    $name = (string) $vector['name'];
    $claims = $vector['claims'];
    $this->assertIsArray($claims, $name);
    $expected = $vector['expected'];
    $this->assertIsArray($expected, $name);

    if (isset($expected['error'])) {
      try {
        McpPrincipalKey::fromClaims($claims);
        $this->fail($name . ' must fail closed (no key).');
      }
      catch (McpPrincipalKeyException $e) {
        $this->assertSame($expected['error'], $e->reasonCode, $name);
      }
      return;
    }

    $got = McpPrincipalKey::fromClaims($claims);
    $this->assertSame($expected['principalKey'], $got['principalKey'], $name);
    $this->assertSame($expected['humanKey'], $got['humanKey'], $name);
    $this->assertArrayNotHasKey('error', $expected, $name);
  }

  /**
   * The fixture is a non-empty array of named vectors.
   */
  public function testVectorFileIsComplete(): void {
    $vectors = self::loadVectors();
    $this->assertNotEmpty($vectors);
    $names = [];
    foreach ($vectors as $vector) {
      $this->assertArrayHasKey('name', $vector);
      $this->assertArrayHasKey('claims', $vector);
      $this->assertArrayHasKey('expected', $vector);
      $names[] = $vector['name'];
    }
    $this->assertContains('no-act-azp-present', $names);
    $this->assertContains('single-act', $names);
    $this->assertContains('nested-act-chain-top-level-actor', $names);
    $this->assertContains('no-act-missing-azp', $names);
    $this->assertContains('missing-sub', $names);
    $this->assertContains('missing-iss', $names);
    $this->assertContains('act-present-missing-act-sub', $names);
    $this->assertContains('pipe-in-sub-rejected', $names);
    $this->assertContains('act-as-string', $names);
    $this->assertContains('act-as-list', $names);
    $this->assertContains('act-as-empty-object', $names);
    $this->assertContains('empty-act-sub', $names);
    $this->assertContains('integer-sub', $names);
    $this->assertContains('whitespace-only-sub', $names);
    $this->assertContains('unicode-sub-valid', $names);
    $this->assertContains('zero-width-sub', $names);
    $this->assertContains('part-too-long-sub', $names);
    $this->assertContains('nbsp-only-sub', $names);
    $this->assertContains('part-too-long-iss', $names);
    $this->assertContains('part-too-long-actor', $names);
    $this->assertSame($names, array_unique($names));
  }

  /**
   * Context helpers match fromClaims for a valid constructed token.
   *
   * @covers ::formatPrincipal
   * @covers ::formatHuman
   */
  public function testContextHelpersMatchFromClaims(): void {
    $ctx = new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-client',
      'agent-client',
      ['mcp_read'],
      'tenant-a',
      ['agent-1', 'B'],
      TRUE,
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'act' => ['sub' => 'agent-1', 'act' => ['sub' => 'B']],
      ],
    );
    $fromClaims = McpPrincipalKey::fromClaims($ctx->keyClaims());
    $this->assertSame(
      $fromClaims['principalKey'],
      McpPrincipalKey::formatPrincipal($ctx),
    );
    $this->assertSame(
      $fromClaims['humanKey'],
      McpPrincipalKey::formatHuman($ctx),
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-1',
      $ctx->principalKey(),
    );
  }

  /**
   * Operator-supplied keys use the same codes as fromClaims().
   *
   * @covers ::parsePrincipalKey
   * @covers ::parseHumanKey
   */
  public function testParseKeyUsesVectorErrorCodes(): void {
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-client',
      McpPrincipalKey::parsePrincipalKey(
        'https://idp.example/realms/agents|human-1|agent-client',
      ),
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      McpPrincipalKey::parseHumanKey('https://idp.example/realms/agents|human-1'),
    );
    try {
      McpPrincipalKey::parsePrincipalKey('https://idp.example/realms/agents|human-1|a|b');
      $this->fail('An extra pipe must be invalid_separator.');
    }
    catch (McpPrincipalKeyException $e) {
      $this->assertSame(McpPrincipalKeyException::INVALID_SEPARATOR, $e->reasonCode);
    }
    try {
      McpPrincipalKey::parseHumanKey('https://idp.example/realms/agents');
      $this->fail('A missing sub must be invalid_part.');
    }
    catch (McpPrincipalKeyException $e) {
      $this->assertSame(McpPrincipalKeyException::INVALID_PART, $e->reasonCode);
    }
  }

  /**
   * Invalid UTF-8 is rejected (not representable in the JSON vectors).
   *
   * @covers ::fromClaims
   */
  public function testInvalidUtf8SubIsRejected(): void {
    $sub = "human\x80";
    $this->assertFalse(mb_check_encoding($sub, 'UTF-8'));
    try {
      McpPrincipalKey::fromClaims([
        'iss' => 'https://idp.example/realms/agents',
        'sub' => $sub,
        'azp' => 'agent-client',
      ]);
      $this->fail('Invalid UTF-8 must fail closed.');
    }
    catch (McpPrincipalKeyException $e) {
      $this->assertSame(McpPrincipalKeyException::INVALID_UTF8, $e->reasonCode);
    }
  }

  /**
   * Vectors keyed by name for one PHPUnit case each.
   *
   * @return array<string, array{0: array<string, mixed>}>
   *   name => [vector].
   */
  public static function vectorProvider(): array {
    $cases = [];
    foreach (self::loadVectors() as $vector) {
      $name = $vector['name'] ?? NULL;
      if (!is_string($name) || $name === '') {
        continue;
      }
      $cases[$name] = [$vector];
    }
    return $cases;
  }

  /**
   * Decodes the language-neutral vector file.
   *
   * @return list<array<string, mixed>>
   *   Vector objects.
   */
  private static function loadVectors(): array {
    $path = dirname(__DIR__, 3) . '/' . McpPrincipalKey::VECTORS_FILE;
    $raw = file_get_contents($path);
    if ($raw === FALSE) {
      throw new \RuntimeException('Unable to read ' . $path);
    }
    $decoded = json_decode($raw, TRUE, 32, JSON_THROW_ON_ERROR);
    if (!is_array($decoded)) {
      throw new \RuntimeException('Vector file must be a JSON array.');
    }
    $vectors = [];
    foreach ($decoded as $item) {
      if (is_array($item)) {
        $vectors[] = $item;
      }
    }
    return $vectors;
  }

}
