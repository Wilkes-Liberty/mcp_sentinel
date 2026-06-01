<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\Merge;
use Drupal\Core\Database\Query\Select;
use Drupal\Core\Database\StatementInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpContentLock
 * @group mcp_sentinel
 */
final class McpContentLockTest extends UnitTestCase {

  /**
   * @covers ::lock
   */
  public function testLockComputesExpiry(): void {
    $captured = [];
    $merge = $this->createMock(Merge::class);
    $merge->method('keys')->willReturnSelf();
    $merge->method('fields')->willReturnCallback(function (array $fields) use (&$captured, $merge) {
      $captured = $fields;
      return $merge;
    });
    $merge->method('execute')->willReturn(1);

    $database = $this->createMock(Connection::class);
    $database->method('merge')->with('mcp_sentinel_content_locks')->willReturn($merge);

    $lock = new McpContentLock($database, $this->mockUser(5), $this->mockTime(1000));
    $lock->lock('node', '7', 'human editing', 3600);

    $this->assertSame(5, $captured['locked_by']);
    $this->assertSame(1000, $captured['locked_at']);
    $this->assertSame(4600, $captured['expires_at']);
    $this->assertSame('human editing', $captured['reason']);
  }

  /**
   * @covers ::lock
   */
  public function testLockWithoutTtlNeverExpires(): void {
    $captured = [];
    $merge = $this->createMock(Merge::class);
    $merge->method('keys')->willReturnSelf();
    $merge->method('fields')->willReturnCallback(function (array $fields) use (&$captured, $merge) {
      $captured = $fields;
      return $merge;
    });
    $merge->method('execute')->willReturn(1);
    $database = $this->createMock(Connection::class);
    $database->method('merge')->willReturn($merge);

    $lock = new McpContentLock($database, $this->mockUser(1), $this->mockTime(1000));
    $lock->lock('node', '7', '', NULL);

    $this->assertSame(0, $captured['expires_at']);
  }

  /**
   * @covers ::isLocked
   */
  public function testIsLockedReflectsCount(): void {
    $database = $this->createMock(Connection::class);

    // isLocked() must NOT write on read — no DELETE during a read.
    $database->expects($this->never())->method('delete');

    // The count query returns "1" (locked). Expired locks are excluded by a
    // query condition rather than a destructive cleanup.
    $statement = $this->createMock(StatementInterface::class);
    $statement->method('fetchField')->willReturn('1');
    $count = $this->createMock(Select::class);
    $count->method('execute')->willReturn($statement);
    $select = $this->createMock(Select::class);
    $select->method('condition')->willReturnSelf();
    $select->method('where')->willReturnSelf();
    $select->method('countQuery')->willReturn($count);
    $database->method('select')->willReturn($select);

    $lock = new McpContentLock($database, $this->mockUser(1), $this->mockTime(1000));
    $this->assertTrue($lock->isLocked('node', '7'));
  }

  /**
   * Builds a mock current user.
   */
  private function mockUser(int $uid): AccountProxyInterface {
    $user = $this->createMock(AccountProxyInterface::class);
    $user->method('id')->willReturn($uid);
    return $user;
  }

  /**
   * Builds a mock time service.
   */
  private function mockTime(int $now): TimeInterface {
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn($now);
    return $time;
  }

}
