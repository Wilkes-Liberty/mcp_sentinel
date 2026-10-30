<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Value\McpCanonicalJson;
use Drupal\mcp_sentinel\Value\McpPolicyBundle;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Oversize audit identity fields are hashed before the chain insert.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpAuditLogger::class)]
#[CoversClass(McpCanonicalJson::class)]
#[Group('mcp_sentinel')]
final class McpAuditLoggerBoundIdentityTest extends UnitTestCase {

  /**
   * A 256-byte id becomes a sha256 digest that fits entity_id.
   *
   * @covers ::boundChainIdentity
   */
  public function testOversizedIdIsReplacedWithDigest(): void {
    $id = str_repeat('a', 256);
    $bounded = McpAuditLogger::boundChainIdentity([
      'id' => $id,
      'reason' => 'part_too_long',
    ]);
    $digest = hash('sha256', $id);
    $this->assertSame('sha256:' . $digest, $bounded['id']);
    $this->assertLessThanOrEqual(255, strlen((string) $bounded['id']));
    $this->assertSame($id, $bounded['id_original']);
    $this->assertArrayNotHasKey('id_sha256', $bounded);
    $this->assertSame('part_too_long', $bounded['reason']);
  }

  /**
   * Values at the column limit are left unchanged.
   *
   * @covers ::boundChainIdentity
   */
  public function testColumnLimitIsUnchanged(): void {
    $id = str_repeat('c', 255);
    $type = str_repeat('t', 128);
    $bounded = McpAuditLogger::boundChainIdentity([
      'id' => $id,
      'entity_type' => $type,
      'bundle' => 'article',
    ]);
    $this->assertSame($id, $bounded['id']);
    $this->assertSame($type, $bounded['entity_type']);
    $this->assertSame('article', $bounded['bundle']);
    $this->assertArrayNotHasKey('id_original', $bounded);
  }

  /**
   * An oversize entity_type is hashed the same way.
   *
   * @covers ::boundChainIdentity
   */
  public function testOversizedEntityTypeIsHashed(): void {
    $type = str_repeat('n', 129);
    $bounded = McpAuditLogger::boundChainIdentity([
      'entity_type' => $type,
    ]);
    $this->assertSame('sha256:' . hash('sha256', $type), $bounded['entity_type']);
    $this->assertSame($type, $bounded['entity_type_original']);
    $this->assertArrayNotHasKey('entity_type_sha256', $bounded);
  }

  /**
   * A non-scalar id is hashed, never cast to Array.
   *
   * @covers ::boundChainIdentity
   */
  public function testNonScalarIdIsHashedDeterministically(): void {
    $id = ['nested' => 'principal'];
    $first = McpAuditLogger::boundChainIdentity(['id' => $id]);
    $second = McpAuditLogger::boundChainIdentity(['id' => $id]);
    $encoded = json_encode(
      $id,
      JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
    );
    $this->assertIsString($encoded);
    $digest = hash('sha256', $encoded);
    $this->assertSame('sha256:' . $digest, $first['id']);
    $this->assertSame($first['id'], $second['id']);
    $this->assertSame($encoded, $first['id_original']);
    $this->assertArrayNotHasKey('id_sha256', $first);
    $this->assertLessThanOrEqual(255, strlen((string) $first['id']));
    $this->assertNotSame('Array', $first['id']);
  }

  /**
   * An object without __toString is hashed, not a TypeError.
   *
   * @covers ::boundChainIdentity
   */
  public function testObjectIdIsHashedNotTypeError(): void {
    $id = new \stdClass();
    $id->x = 1;
    $bounded = McpAuditLogger::boundChainIdentity(['id' => $id]);
    $this->assertTrue(
      (bool) preg_match('/^sha256:[0-9a-f]{64}$/', (string) $bounded['id']),
      'A non-scalar object must become a sha256 digest, not a TypeError.',
    );
    $this->assertArrayHasKey('id_original', $bounded);
    $this->assertArrayNotHasKey('id_sha256', $bounded);
  }

  /**
   * A throwing jsonSerialize() falls back to the type marker.
   *
   * Encoding can propagate that exception even without
   * JSON_THROW_ON_ERROR. The digest must still be written.
   *
   * @covers ::boundChainIdentity
   */
  public function testThrowingSerializerFallsBackToTypeMarker(): void {
    $id = new class() implements \JsonSerializable {

      /**
       * {@inheritdoc}
       */
      public function jsonSerialize(): never {
        throw new \RuntimeException('cannot serialize');
      }

    };
    $bounded = McpAuditLogger::boundChainIdentity(['id' => $id]);
    $marker = '{"type":"' . get_debug_type($id) . '"}';
    $this->assertSame($marker, $bounded['id_original']);
    $this->assertSame('sha256:' . hash('sha256', $marker), $bounded['id']);
    $this->assertArrayNotHasKey('id_sha256', $bounded);
    $this->assertLessThanOrEqual(255, strlen((string) $bounded['id']));
  }

  /**
   * Nested maps hash the same regardless of key insertion order.
   *
   * @covers ::boundChainIdentity
   */
  public function testReorderedMapsShareTheSameDigest(): void {
    $first = McpAuditLogger::boundChainIdentity([
      'id' => ['b' => 2, 'a' => ['z' => 1, 'y' => 2]],
    ]);
    $second = McpAuditLogger::boundChainIdentity([
      'id' => ['a' => ['y' => 2, 'z' => 1], 'b' => 2],
    ]);
    $this->assertSame('{"a":{"y":2,"z":1},"b":2}', $first['id_original']);
    $this->assertSame($first['id_original'], $second['id_original']);
    $this->assertSame($first['id'], $second['id']);
    $this->assertSame('sha256:' . hash('sha256', $first['id_original']), $first['id']);
    $this->assertArrayNotHasKey('id_sha256', $first);
  }

  /**
   * An empty list encodes as [] and an empty object as {}.
   *
   * @covers ::boundChainIdentity
   */
  public function testEmptyListAndObjectKeepJsonTypes(): void {
    $list = McpAuditLogger::boundChainIdentity(['id' => []]);
    $object = McpAuditLogger::boundChainIdentity(['id' => new \stdClass()]);
    $this->assertSame('[]', $list['id_original']);
    $this->assertSame('{}', $object['id_original']);
    $this->assertNotSame($list['id'], $object['id']);
  }

  /**
   * Identity hashes use the same map sort as policy-bundle claims.
   *
   * @covers ::boundChainIdentity
   */
  public function testIdentityAndPolicyShareMapCanonicalization(): void {
    $map = ['b' => 2, 'a' => ['z' => 1, 'y' => 2]];
    $policy = json_encode(
      McpPolicyBundle::normalize($map),
      JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
    );
    $this->assertIsString($policy);
    $identity = McpAuditLogger::boundChainIdentity(['id' => $map]);
    $this->assertSame($policy, $identity['id_original']);
  }

  /**
   * A self-referencing object falls back to the type marker.
   *
   * Without MAX_DEPTH this recurses until a fatal and the deny
   * path never writes a row.
   *
   * @covers ::boundChainIdentity
   */
  public function testSelfReferencingObjectFallsBackToTypeMarker(): void {
    $id = new \stdClass();
    $id->self = $id;
    $bounded = McpAuditLogger::boundChainIdentity(['id' => $id]);
    $marker = '{"type":"' . get_debug_type($id) . '"}';
    $this->assertSame($marker, $bounded['id_original']);
    $this->assertSame('sha256:' . hash('sha256', $marker), $bounded['id']);
    $this->assertLessThanOrEqual(255, strlen((string) $bounded['id']));
  }

  /**
   * A JsonSerializable that returns itself falls back to the marker.
   *
   * @covers ::boundChainIdentity
   */
  public function testSelfJsonSerializeFallsBackToTypeMarker(): void {
    $id = new class() implements \JsonSerializable {

      /**
       * {@inheritdoc}
       */
      public function jsonSerialize(): mixed {
        return $this;
      }

    };
    $bounded = McpAuditLogger::boundChainIdentity(['id' => $id]);
    $marker = '{"type":"' . get_debug_type($id) . '"}';
    $this->assertSame($marker, $bounded['id_original']);
    $this->assertSame('sha256:' . hash('sha256', $marker), $bounded['id']);
    $this->assertLessThanOrEqual(255, strlen((string) $bounded['id']));
  }

}
