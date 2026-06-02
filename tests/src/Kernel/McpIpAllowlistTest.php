<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests per-profile IP allowlisting in McpAccessChecker.
 *
 * Security surface verified:
 * - A client IP inside the allowed CIDR is permitted.
 * - A client IP outside the allowed CIDR is denied.
 * - An empty allowed_ips list permits all IPs.
 * - IPv6 CIDRs work.
 * - A spoofed X-Forwarded-For header is NOT honored unless trusted proxies
 *   are configured — proving getClientIp() is used, not raw header reads.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAccessChecker
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpIpAllowlistTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key',
    'image', 'options', 'path_alias', 'consumers', 'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * A node used across access assertions.
   */
  private Node $node;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $this->node = Node::create(['type' => 'article', 'title' => 'Test']);
    // Enable MCP Sentinel globally.
    $this->config('mcp_sentinel.settings')->set('enabled', TRUE)->save();
  }

  /**
   * Returns the access checker service.
   */
  private function checker(): McpAccessChecker {
    return $this->container->get('mcp_sentinel.access_checker');
  }

  /**
   * Builds a request with REMOTE_ADDR, pushes it, and returns it for cleanup.
   *
   * @param string $remoteAddr
   *   The connecting IP (as seen by the server socket).
   * @param string $xForwardedFor
   *   Optional X-Forwarded-For header value.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The pushed request.
   */
  private function pushRequest(
    string $remoteAddr,
    string $xForwardedFor = '',
  ): Request {
    $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $remoteAddr]);
    if ($xForwardedFor !== '') {
      $request->headers->set('X-Forwarded-For', $xForwardedFor);
    }
    // Do NOT set trusted proxies — intentionally absent to prove spoofing
    // is impossible without them.
    /** @var \Symfony\Component\HttpFoundation\RequestStack $stack */
    $stack = $this->container->get('request_stack');
    $stack->push($request);
    return $request;
  }

  /**
   * Creates a policy profile with the given allowed_ips.
   *
   * @param string[] $allowedIps
   *   IP addresses and/or CIDR blocks.
   *
   * @return \Drupal\mcp_sentinel\Entity\McpPolicyProfile
   *   An unsaved profile entity.
   */
  private function profileWithIps(array $allowedIps): McpPolicyProfile {
    return McpPolicyProfile::create([
      'id' => 'ip_test_' . substr(md5(serialize($allowedIps)), 0, 6),
      'label' => 'IP Test',
      'allow_read' => TRUE,
      'allow_write' => TRUE,
      'allowed_ips' => $allowedIps,
    ]);
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testIpInCidrAllowlistIsAllowed(): void {
    $profile = $this->profileWithIps(['203.0.113.0/24']);
    $this->pushRequest('203.0.113.42');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertFalse($result->isForbidden(), 'IP 203.0.113.42 inside /24 block must be allowed.');
    $this->container->get('request_stack')->pop();
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testIpOutsideCidrIsDenied(): void {
    $profile = $this->profileWithIps(['203.0.113.0/24']);
    $this->pushRequest('192.0.2.1');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertTrue($result->isForbidden(), 'IP 192.0.2.1 outside /24 block must be denied.');
    $this->assertInstanceOf(AccessResultReasonInterface::class, $result);
    $this->assertStringContainsString(
      'Source IP not permitted',
      $result->getReason(),
      'Reason must mention source IP.'
    );
    $this->container->get('request_stack')->pop();
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testEmptyAllowlistPermitsAllIps(): void {
    $profile = $this->profileWithIps([]);
    $this->pushRequest('1.2.3.4');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertFalse($result->isForbidden(), 'Empty allowed_ips must permit any IP.');
    $this->container->get('request_stack')->pop();
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testIpv6CidrAllowlistWorks(): void {
    $profile = $this->profileWithIps(['2001:db8::/32']);
    // An address inside 2001:db8::/32.
    $this->pushRequest('2001:db8::1');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertFalse($result->isForbidden(), 'IPv6 address inside /32 block must be allowed.');
    $this->container->get('request_stack')->pop();

    // An address outside 2001:db8::/32.
    $this->pushRequest('2001:db9::1');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertTrue($result->isForbidden(), 'IPv6 address outside /32 block must be denied.');
    $this->container->get('request_stack')->pop();
  }

  /**
   * Proves a spoofed XFF does NOT bypass the allowlist without trusted proxies.
   *
   * Critical anti-spoofing test: attacker sets X-Forwarded-For to an allowed
   * IP while connecting from a blocked IP. Without trusted proxies configured,
   * Symfony's getClientIp() returns REMOTE_ADDR (the real socket IP) and
   * ignores X-Forwarded-For, so the allowlist check denies the request.
   *
   * @covers ::checkEntityAccess
   */
  public function testSpoofedXffDoesNotBypassAllowlist(): void {
    // Allowlist allows only 203.0.113.0/24.
    $profile = $this->profileWithIps(['203.0.113.0/24']);

    // Attacker: REMOTE_ADDR=192.0.2.1 (blocked) + XFF=203.0.113.1 (allowed).
    // No trusted proxies configured — getClientIp() must return REMOTE_ADDR.
    $request = $this->pushRequest('192.0.2.1', '203.0.113.1');

    // Assert getClientIp() ignores the spoofed XFF when no proxies are trusted.
    $this->assertSame(
      '192.0.2.1',
      $request->getClientIp(),
      'Without trusted proxies, getClientIp() must return REMOTE_ADDR, not XFF.'
    );

    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertTrue(
      $result->isForbidden(),
      'Spoofed XFF must not bypass the IP allowlist.'
    );

    $this->container->get('request_stack')->pop();
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testSingleIpAllowlistWorks(): void {
    $profile = $this->profileWithIps(['198.51.100.7']);
    $this->pushRequest('198.51.100.7');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertFalse($result->isForbidden(), 'Exact matching IP must be allowed.');
    $this->container->get('request_stack')->pop();

    $this->pushRequest('198.51.100.8');
    $result = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertTrue($result->isForbidden(), 'Non-matching IP must be denied.');
    $this->container->get('request_stack')->pop();
  }

  /**
   * Verifies the profile schema stores and retrieves allowed_ips correctly.
   *
   * @covers \Drupal\mcp_sentinel\Entity\McpPolicyProfile::getAllowedIps
   */
  public function testProfileFieldPersistsAllowedIps(): void {
    McpPolicyProfile::create([
      'id' => 'ip_persist_test',
      'label' => 'IP Persist Test',
      'allowed_ips' => ['10.0.0.0/8', '192.168.1.1'],
    ])->save();

    $loaded = McpPolicyProfile::load('ip_persist_test');
    $this->assertInstanceOf(McpPolicyProfile::class, $loaded);
    $this->assertSame(
      ['10.0.0.0/8', '192.168.1.1'],
      $loaded->getAllowedIps(),
      'allowed_ips must persist and be retrieved correctly.'
    );
  }

  /**
   * Verifies the default profile has an empty allowed_ips (no restriction).
   *
   * @covers \Drupal\mcp_sentinel\Entity\McpPolicyProfile::getAllowedIps
   */
  public function testDefaultProfileHasEmptyAllowedIps(): void {
    $default = McpPolicyProfile::load('default');
    $this->assertInstanceOf(McpPolicyProfile::class, $default);
    $this->assertSame(
      [],
      $default->getAllowedIps(),
      'Default profile must have empty allowed_ips (no restriction).'
    );
  }

  /**
   * Proves the "allowed" result is uncacheable when allowed_ips is non-empty.
   *
   * Cache bypass scenario: if the allowed result were cacheable, Drupal's
   * entity-access cache could re-serve it to a later request from the same
   * account/roles but a DIFFERENT, disallowed IP — bypassing the gate entirely.
   * Client IP is not a Drupal cache context, so the only safe answer is
   * max-age 0 on every result returned when a profile has IP restrictions.
   *
   * Test steps:
   *  A) Allowed IP (203.0.113.42 in /24): result must be NOT forbidden AND
   *     getCacheMaxAge() === 0.
   *  B) Disallowed IP (192.0.2.1): result must be forbidden (gate re-applies).
   *
   * @covers ::checkEntityAccess
   * @covers ::isClientIpAllowed
   */
  public function testCachedAllowedResultDoesNotServeDeniedIp(): void {
    $profile = $this->profileWithIps(['203.0.113.0/24']);

    // Step A: request from an allowed IP.
    $this->pushRequest('203.0.113.42');
    $allowed = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertFalse(
      $allowed->isForbidden(),
      'IP 203.0.113.42 inside /24 must not be forbidden.'
    );
    $this->assertSame(
      0,
      $allowed->getCacheMaxAge(),
      'Allowed result must be uncacheable (max-age 0) when profile has IP restrictions — a cached allowed result could bypass the gate for a different IP.'
    );
    $this->container->get('request_stack')->pop();

    // Step B: request from a disallowed IP — gate must re-evaluate and deny.
    $this->pushRequest('192.0.2.1');
    $denied = $this->checker()->checkEntityAccess($this->node, 'view', $profile);
    $this->assertTrue(
      $denied->isForbidden(),
      'IP 192.0.2.1 must be forbidden even after a prior allowed result.'
    );
    $this->container->get('request_stack')->pop();
  }

}
