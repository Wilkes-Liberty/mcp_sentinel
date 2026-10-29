<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * audit_chain_log.entity_id is varchar(255); longer ids are truncated.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpAuditLogger::class)]
#[Group('mcp_sentinel')]
final class McpAuditLoggerEntityIdBoundTest extends UnitTestCase {

  /**
   * A legal 256-character JWT subject does not fit the column.
   *
   * @covers ::boundedEntityId
   */
  public function testBoundedEntityIdTruncatesMaxPartSubject(): void {
    $subject = str_repeat('s', 256);
    $bounded = McpAuditLogger::boundedEntityId($subject);
    $this->assertSame(
      McpAuditLogger::ENTITY_ID_MAX_LENGTH,
      mb_strlen($bounded, 'UTF-8'),
    );
    $this->assertSame(str_repeat('s', 255), $bounded);
    $this->assertSame('short', McpAuditLogger::boundedEntityId('short'));
  }

}
