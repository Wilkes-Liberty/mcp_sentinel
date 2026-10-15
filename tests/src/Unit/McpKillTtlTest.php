<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kill-block TTL default and 7 d cap (DEV-846).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpKillTtl
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpKillTtl::class)]
#[Group('mcp_sentinel')]
final class McpKillTtlTest extends UnitTestCase {

  /**
   * NULL request uses the 24 h default.
   *
   * @covers ::resolve
   */
  public function testDefaultTtlIs24Hours(): void {
    $this->assertSame(86400, McpKillTtl::resolve(NULL));
    $this->assertSame(McpKillTtl::DEFAULT, McpKillTtl::resolve(NULL));
  }

  /**
   * A requested TTL above 7 d is capped.
   *
   * @covers ::resolve
   */
  public function testRequestedTtlIsCappedAt7Days(): void {
    $this->assertSame(McpKillTtl::MAX, McpKillTtl::resolve(McpKillTtl::MAX + 1));
    $this->assertSame(McpKillTtl::MAX, McpKillTtl::resolve(10 * 86400));
  }

  /**
   * A positive requested TTL below the cap is kept.
   *
   * @covers ::resolve
   */
  public function testRequestedTtlBelowCapIsKept(): void {
    $this->assertSame(3600, McpKillTtl::resolve(3600));
  }

  /**
   * Zero or negative TTL is refused.
   *
   * @covers ::resolve
   */
  public function testNonPositiveTtlIsRefused(): void {
    $this->expectException(McpKillSwitchException::class);
    $this->expectExceptionMessage('positive number of seconds');
    McpKillTtl::resolve(0);
  }

  /**
   * Block_until is now plus the resolved TTL.
   *
   * @covers ::blockUntil
   */
  public function testBlockUntilIsNowPlusTtl(): void {
    $this->assertSame(1_700_000_000 + 86400, McpKillTtl::blockUntil(1_700_000_000, 86400));
  }

}
