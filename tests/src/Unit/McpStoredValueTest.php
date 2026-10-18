<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Value\McpStoredValue;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Strict mixed-to-scalar readers for stored rows.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpStoredValue
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpStoredValue::class)]
#[Group('mcp_sentinel')]
final class McpStoredValueTest extends UnitTestCase {

  /**
   * Strings and numbers become strings; everything else is empty.
   *
   * @covers ::string
   */
  public function testStringKeepsScalars(): void {
    $this->assertSame('held', McpStoredValue::string('held'));
    $this->assertSame('7', McpStoredValue::string(7));
    $this->assertSame('1.5', McpStoredValue::string(1.5));
    $this->assertSame('', McpStoredValue::string(NULL));
    $this->assertSame('', McpStoredValue::string(TRUE));
    $this->assertSame('', McpStoredValue::string(['x']));
  }

  /**
   * Ints and numeric values become ints; bools and objects are 0.
   *
   * @covers ::int
   */
  public function testIntKeepsNumericValues(): void {
    $this->assertSame(7, McpStoredValue::int(7));
    $this->assertSame(7, McpStoredValue::int('7'));
    $this->assertSame(1, McpStoredValue::int(1.9));
    $this->assertSame(0, McpStoredValue::int(NULL));
    $this->assertSame(0, McpStoredValue::int(TRUE));
    $this->assertSame(0, McpStoredValue::int(['1']));
  }

  /**
   * Row helpers read the named column through the same rules.
   *
   * @covers ::rowString
   * @covers ::rowInt
   */
  public function testRowHelpersReadNamedColumns(): void {
    $row = [
      'status' => 'killed',
      'ttl' => '3600',
      'attempts' => 2,
    ];
    $this->assertSame('killed', McpStoredValue::rowString($row, 'status'));
    $this->assertSame('', McpStoredValue::rowString($row, 'missing'));
    $this->assertSame(3600, McpStoredValue::rowInt($row, 'ttl'));
    $this->assertSame(2, McpStoredValue::rowInt($row, 'attempts'));
    $this->assertSame(0, McpStoredValue::rowInt($row, 'missing'));
  }

  /**
   * A non-array or a non-string key makes the whole row unreadable.
   *
   * @covers ::stringKeyedRow
   */
  public function testStringKeyedRowRejectsBadKeys(): void {
    $this->assertNull(McpStoredValue::stringKeyedRow(NULL));
    $this->assertNull(McpStoredValue::stringKeyedRow('row'));
    $this->assertNull(McpStoredValue::stringKeyedRow([0 => 'x']));
    $this->assertSame(
      ['status' => 'held'],
      McpStoredValue::stringKeyedRow(['status' => 'held']),
    );
  }

}
