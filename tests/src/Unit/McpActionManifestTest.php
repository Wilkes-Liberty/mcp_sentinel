<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Value\McpActionManifest;
use Drupal\mcp_sentinel\Value\McpCanonicalJson;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Canonical encoding and claim-shape rules for action manifests.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpActionManifest
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpActionManifest::class)]
#[CoversClass(McpCanonicalJson::class)]
#[Group('mcp_sentinel')]
final class McpActionManifestTest extends UnitTestCase {

  /**
   * Claim key order is sorted and stable across input order.
   */
  public function testCanonicalJsonIsStableAcrossKeyOrder(): void {
    $a = [
      'v' => 1,
      'id' => 'aaa',
      'actor_uid' => 2,
      'delegation' => [
        'request_id' => 'r1',
        'consumer_client_id' => 'c1',
      ],
      'operation' => 'delete',
      'arguments' => ['entity_id' => '4', 'entity_type' => 'node'],
      'target' => [
        'revision' => '7',
        'type' => 'node',
        'uuid' => 'u',
        'id' => '4',
      ],
      'policy_digest' => 'sha256:x',
      'preconditions' => ['target_uuid', 'target_revision'],
      'expires' => 10,
      'idempotency_key' => 'ik',
    ];
    $b = [
      'idempotency_key' => 'ik',
      'expires' => 10,
      'preconditions' => ['target_uuid', 'target_revision'],
      'policy_digest' => 'sha256:x',
      'target' => [
        'id' => '4',
        'uuid' => 'u',
        'type' => 'node',
        'revision' => '7',
      ],
      'arguments' => ['entity_type' => 'node', 'entity_id' => '4'],
      'operation' => 'delete',
      'delegation' => [
        'consumer_client_id' => 'c1',
        'request_id' => 'r1',
      ],
      'actor_uid' => 2,
      'id' => 'aaa',
      'v' => 1,
    ];
    $this->assertSame(
      McpActionManifest::canonicalJson($a),
      McpActionManifest::canonicalJson($b),
    );
    $this->assertTrue(McpActionManifest::hasClaimShape($a));
  }

  /**
   * List order is part of the contract and is not sorted.
   */
  public function testListOrderIsPreserved(): void {
    $first = McpActionManifest::canonicalJson([
      'preconditions' => ['target_uuid', 'target_revision'],
    ]);
    $second = McpActionManifest::canonicalJson([
      'preconditions' => ['target_revision', 'target_uuid'],
    ]);
    $this->assertNotSame($first, $second);
  }

  /**
   * An extra or missing claim key is not a valid document.
   */
  public function testUnknownClaimKeyFailsShape(): void {
    $claims = $this->completeClaims();
    $this->assertTrue(McpActionManifest::hasClaimShape($claims));
    $claims['extra'] = 'nope';
    $this->assertFalse(McpActionManifest::hasClaimShape($claims));
    unset($claims['extra'], $claims['operation']);
    $this->assertFalse(McpActionManifest::hasClaimShape($claims));
  }

  /**
   * Objects and resources cannot be encoded.
   */
  public function testNonScalarValueIsRejected(): void {
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage(
      'Manifest claims may only contain scalars, lists and maps.',
    );
    McpActionManifest::canonicalJson([
      'arguments' => ['bad' => new \stdClass()],
    ]);
  }

  /**
   * Manifest normalize matches McpCanonicalJson on maps and scalars.
   *
   * @covers ::normalize
   * @covers \Drupal\mcp_sentinel\Value\McpCanonicalJson::normalize
   */
  public function testNormalizeAgreesWithCanonicalJson(): void {
    $cases = [
      'empty list' => [],
      'list' => ['b', 'a'],
      'map' => ['z' => 1, 'a' => 2],
      'nested map and list' => [
        'z' => ['b' => 2, 'a' => 1],
        'a' => ['x', 'y'],
        'empty' => [],
      ],
      'null' => NULL,
      'bool' => FALSE,
      'int' => 0,
      'float' => 1.5,
      'string' => 'slash/path',
    ];
    foreach ($cases as $label => $value) {
      $this->assertSame(
        McpCanonicalJson::normalize($value),
        McpActionManifest::normalize($value),
        $label,
      );
    }
  }

  /**
   * The sorter lives in McpCanonicalJson; this class must not copy it.
   *
   * @covers ::normalize
   */
  public function testNormalizeDoesNotCopyTheSorter(): void {
    $file = (new \ReflectionClass(McpActionManifest::class))->getFileName();
    $this->assertNotFalse($file);
    $source = file_get_contents($file);
    $this->assertNotFalse($source);
    $this->assertStringContainsString('McpCanonicalJson::normalize', $source);
    $this->assertDoesNotMatchRegularExpression('/\bksort\s*\(/', $source);
  }

  /**
   * An acyclic nest deeper than MAX_DEPTH is rejected.
   *
   * @covers ::normalize
   */
  public function testNormalizeRejectsGraphDeeperThanMaxDepth(): void {
    $value = 'leaf';
    for ($i = 0; $i < McpCanonicalJson::MAX_DEPTH + 1; $i++) {
      $value = [$value];
    }
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessage('Canonical JSON depth exceeded.');
    McpActionManifest::normalize($value);
  }

  /**
   * A nest of exactly MAX_DEPTH arrays is accepted.
   *
   * @covers ::normalize
   */
  public function testNormalizeAcceptsGraphAtMaxDepth(): void {
    $value = 'leaf';
    for ($i = 0; $i < McpCanonicalJson::MAX_DEPTH; $i++) {
      $value = [$value];
    }
    $normalized = McpActionManifest::normalize($value);
    for ($i = 0; $i < McpCanonicalJson::MAX_DEPTH; $i++) {
      $this->assertIsArray($normalized);
      $this->assertCount(1, $normalized);
      $normalized = $normalized[0];
    }
    $this->assertSame('leaf', $normalized);
  }

  /**
   * A manifest wider than MAX_NODES still matches the shared helper.
   *
   * Node and byte budgets are identity-only.
   *
   * @covers ::normalize
   */
  public function testNormalizeAcceptsManifestWiderThanNodeBudget(): void {
    $arguments = [];
    for ($i = 0; $i < McpCanonicalJson::MAX_NODES + 4; $i++) {
      $arguments['k' . $i] = 'v' . $i;
    }
    $value = ['arguments' => $arguments];
    $this->assertSame(
      McpCanonicalJson::normalize($value),
      McpActionManifest::normalize($value),
    );
  }

  /**
   * A 70 KiB argument string still matches the shared helper.
   *
   * @covers ::normalize
   */
  public function testNormalizeAcceptsManifestStringOverByteBudget(): void {
    $value = ['arguments' => ['blob' => str_repeat('x', 70 * 1024)]];
    $this->assertSame(
      McpCanonicalJson::normalize($value),
      McpActionManifest::normalize($value),
    );
  }

  /**
   * Canonical JSON bytes are pinned so a sorter drift fails this test.
   *
   * @covers ::canonicalJson
   * @covers ::normalize
   */
  public function testCanonicalJsonBytesArePinned(): void {
    $this->assertSame(
      '{"actor_uid":2,"arguments":[],"delegation":{"consumer_client_id":null,'
      . '"request_id":null},"expires":1,"id":"aaa","idempotency_key":"ik",'
      . '"operation":"delete","policy_digest":null,"preconditions":[],'
      . '"target":{"id":"1","revision":null,"type":"node","uuid":null},"v":1}',
      McpActionManifest::canonicalJson($this->completeClaims()),
    );
  }

  /**
   * The JSON document carries the seal, never the signing key.
   */
  public function testToArrayCarriesSealNotKey(): void {
    $claims = $this->completeClaims();
    $manifest = McpActionManifest::fromVerifiedClaims(
      json_decode(McpActionManifest::canonicalJson($claims), TRUE),
      'hmac-sha256:abc',
    );
    $encoded = $manifest->toJson();
    $this->assertStringContainsString('"seal":"hmac-sha256:abc"', $encoded);
    $this->assertStringNotContainsString('key_value', $encoded);
    $this->assertStringNotContainsString('hash_key', $encoded);
    $this->assertSame('aaa', $manifest->id());
    $this->assertSame(2, $manifest->actorUid());
    $this->assertSame('delete', $manifest->operation());
  }

  /**
   * A complete claims document.
   *
   * @return array<string, mixed>
   *   Claims.
   */
  private function completeClaims(): array {
    return [
      'v' => 1,
      'id' => 'aaa',
      'actor_uid' => 2,
      'delegation' => [
        'consumer_client_id' => NULL,
        'request_id' => NULL,
      ],
      'operation' => 'delete',
      'arguments' => [],
      'target' => [
        'type' => 'node',
        'id' => '1',
        'uuid' => NULL,
        'revision' => NULL,
      ],
      'policy_digest' => NULL,
      'preconditions' => [],
      'expires' => 1,
      'idempotency_key' => 'ik',
    ];
  }

}
