<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\SelectInterface;
use Drupal\mcp_sentinel\Service\McpAuditOperationQuery;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Shared audit operation matcher.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditOperationQuery
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpAuditOperationQuery::class)]
#[Group('mcp_sentinel')]
final class McpAuditOperationQueryTest extends UnitTestCase {

  /**
   * A NULL count-query execute() is 0, not a fatal.
   *
   * @covers ::countMatching
   */
  public function testCountMatchingTreatsNullExecuteAsZero(): void {
    $select = $this->createMock(SelectInterface::class);
    $select->method('condition')->willReturnSelf();
    $select->method('countQuery')->willReturnSelf();
    $select->method('execute')->willReturn(NULL);
    $database = $this->createMock(Connection::class);
    $database->method('select')->willReturn($select);

    $this->assertSame(
      0,
      McpAuditOperationQuery::countMatching($database, 'denied_access', 1),
    );
  }

}
