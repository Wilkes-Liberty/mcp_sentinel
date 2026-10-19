<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpKillBlockUntilReader;
use Drupal\mcp_sentinel_test\Service\McpTestKillBlockUntilReader;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Typed block_until reader and the test-module decorator.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpKillBlockUntilReader
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpKillBlockUntilReader::class)]
#[CoversClass(McpTestKillBlockUntilReader::class)]
#[Group('mcp_sentinel')]
final class McpKillBlockUntilReaderTest extends UnitTestCase {

  /**
   * Production reads integers and numeric strings; garbage is NULL.
   *
   * @covers ::read
   */
  public function testProductionRead(): void {
    $reader = new McpKillBlockUntilReader();
    $this->assertSame(1700000000, $reader->read(['block_until' => 1700000000]));
    $this->assertSame(1700000000, $reader->read(['block_until' => '1700000000']));
    $this->assertNull($reader->read(['block_until' => 'not-a-number']));
    $this->assertNull($reader->read([]));
  }

  /**
   * The decorator fails closed for one batch, then the rest stay typed.
   *
   * @covers \Drupal\mcp_sentinel_test\Service\McpTestKillBlockUntilReader::injectUnreadable
   * @covers \Drupal\mcp_sentinel_test\Service\McpTestKillBlockUntilReader::read
   */
  public function testDecoratorHonoursBatchId(): void {
    $reader = new McpTestKillBlockUntilReader(new McpKillBlockUntilReader());
    $row = [
      'batch_id' => 'batch-a',
      'block_until' => 1700000000,
    ];
    $other = [
      'batch_id' => 'batch-b',
      'block_until' => 1700000000,
    ];
    $this->assertSame(1700000000, $reader->read($row));
    $reader->injectUnreadable('batch-a');
    $this->assertNull($reader->read($row));
    $this->assertSame(1700000000, $reader->read($other));
    $reader->injectUnreadable('');
    $this->assertNull($reader->read($other));
  }

}
