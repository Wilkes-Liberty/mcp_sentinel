<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the McpWebhookWorker SSRF guard and backoff schedule.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Plugin\QueueWorker\McpWebhookWorker
 * @group mcp_sentinel
 */
final class McpWebhookWorkerTest extends TestCase {

  /**
   * The backoff schedule returns 30 s, 5 m, 30 m, 2 h, 8 h and clamps.
   *
   * @covers ::backoffSeconds
   */
  public function testBackoffSchedule(): void {
    $this->assertSame(30, McpWebhookWorker::backoffSeconds(1));
    $this->assertSame(300, McpWebhookWorker::backoffSeconds(2));
    $this->assertSame(1800, McpWebhookWorker::backoffSeconds(3));
    $this->assertSame(7200, McpWebhookWorker::backoffSeconds(4));
    $this->assertSame(28800, McpWebhookWorker::backoffSeconds(5));
    // Out-of-range attempts clamp to the ends of the schedule.
    $this->assertSame(30, McpWebhookWorker::backoffSeconds(0));
    $this->assertSame(28800, McpWebhookWorker::backoffSeconds(9));
  }

  /**
   * Private, loopback, link-local and reserved IPs are flagged internal.
   *
   * @covers ::ipIsInternal
   * @dataProvider internalIpProvider
   */
  public function testInternalIpsBlocked(string $ip): void {
    $this->assertTrue(
      McpWebhookWorker::ipIsInternal($ip),
      sprintf('%s should be treated as internal.', $ip),
    );
  }

  /**
   * Public, routable IPs are not flagged internal.
   *
   * @covers ::ipIsInternal
   * @dataProvider publicIpProvider
   */
  public function testPublicIpsAllowed(string $ip): void {
    $this->assertFalse(
      McpWebhookWorker::ipIsInternal($ip),
      sprintf('%s should be treated as public.', $ip),
    );
  }

  /**
   * Internal/reserved IP fixtures.
   *
   * @return array<int, array<int, string>>
   *   Data rows of internal IPs.
   */
  public static function internalIpProvider(): array {
    return [
      ['127.0.0.1'],
      ['10.0.0.5'],
      ['10.255.255.255'],
      ['172.16.0.1'],
      ['172.31.255.254'],
      ['192.168.1.1'],
      ['169.254.10.10'],
      ['0.0.0.0'],
      ['::1'],
      ['fc00::1'],
      ['fe80::1'],
    ];
  }

  /**
   * Public IP fixtures.
   *
   * @return array<int, array<int, string>>
   *   Data rows of public IPs.
   */
  public static function publicIpProvider(): array {
    return [
      ['8.8.8.8'],
      ['1.1.1.1'],
      ['93.184.216.34'],
      ['2606:2800:220:1:248:1893:25c8:1946'],
    ];
  }

}
