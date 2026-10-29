<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpAuditLogger;
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
    $this->assertSame($digest, $bounded['id_sha256']);
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
  }

}
