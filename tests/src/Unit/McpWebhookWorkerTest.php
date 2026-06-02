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
   * An internal IPv6 (AAAA) result blocks the whole destination, fail-closed.
   *
   * This is the IPv6-only (AAAA) SSRF case: a hostname that resolves ONLY to an
   * internal IPv6 address must be blocked. classifyResolvedIps() is the pure
   * extraction of validateAndResolveHost()'s policy, so we can assert the block
   * without mocking DNS.
   *
   * @covers ::classifyResolvedIps
   * @dataProvider internalIpv6ResolutionProvider
   */
  public function testInternalIpv6ResolutionBlocked(array $ips): void {
    $this->assertNull(
      McpWebhookWorker::classifyResolvedIps($ips),
      sprintf('Resolution %s containing an internal IPv6 must be blocked.', implode(',', $ips)),
    );
  }

  /**
   * A mixed result with any internal IP (v4 or v6) blocks fail-closed.
   *
   * @covers ::classifyResolvedIps
   */
  public function testMixedResolutionWithInternalIpv6Blocked(): void {
    // Public IPv4 + internal IPv6 → blocked (attacker cannot smuggle ::1).
    $this->assertNull(McpWebhookWorker::classifyResolvedIps(['93.184.216.34', '::1']));
    // Public IPv6 + internal IPv4 → blocked.
    $this->assertNull(McpWebhookWorker::classifyResolvedIps(['2606:2800:220:1:248:1893:25c8:1946', '10.0.0.5']));
  }

  /**
   * A purely public resolution returns the first public IP to pin.
   *
   * @covers ::classifyResolvedIps
   */
  public function testPublicResolutionReturnsFirstIp(): void {
    $this->assertSame('93.184.216.34', McpWebhookWorker::classifyResolvedIps(['93.184.216.34', '8.8.8.8']));
    // IPv6-only public resolution returns the public IPv6 for pinning.
    $this->assertSame(
      '2606:2800:220:1:248:1893:25c8:1946',
      McpWebhookWorker::classifyResolvedIps(['2606:2800:220:1:248:1893:25c8:1946']),
    );
    // An empty resolution returns FALSE (let the HTTP layer fail it normally).
    $this->assertFalse(McpWebhookWorker::classifyResolvedIps([]));
  }

  /**
   * An IPv6 pin entry is bracket-wrapped; IPv4 is not.
   *
   * @covers ::curlResolveEntry
   */
  public function testCurlResolveEntryBracketsIpv6(): void {
    $this->assertSame(
      'example.com:443:[2606:2800:220:1:248:1893:25c8:1946]',
      McpWebhookWorker::curlResolveEntry('example.com', 443, '2606:2800:220:1:248:1893:25c8:1946'),
    );
    $this->assertSame(
      'example.com:443:93.184.216.34',
      McpWebhookWorker::curlResolveEntry('example.com', 443, '93.184.216.34'),
    );
  }

  /**
   * IPv6-only (AAAA) internal-resolution fixtures.
   *
   * @return array<int, array<int, array<int, string>>>
   *   Data rows of resolved-IP lists that must be blocked.
   */
  public static function internalIpv6ResolutionProvider(): array {
    return [
      [['::1']],
      [['fc00::1']],
      [['fd00::abcd']],
      [['fe80::1']],
    ];
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
