<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Value\McpActionManifest;
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
    McpActionManifest::canonicalJson([
      'arguments' => ['bad' => new \stdClass()],
    ]);
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
