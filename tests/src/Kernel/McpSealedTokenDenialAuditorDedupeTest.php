<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use ColinODell\PsrTestLogger\TestLogger;
use Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason;
use Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Sealed-token denial rows collapse per reason, principal, and window.
 *
 * Site and path stay on the chain row. They must not be part of the
 * dedupe key: both come from the request and are attacker-chosen.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSealedTokenDenialAuditor::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSealedTokenDenialAuditorDedupeTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'image',
    'options',
    'path_alias',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * Test clock shared by the auditor under test.
   */
  private McpSealedTokenDenyAuditTestClock $clock;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installSchema('user', ['users_data']);
    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->installConfig(['mcp_sentinel', 'system']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_sealed_token']);
    $this->pushRequestKeepingSession(
      Request::create('https://sentinel.example/jsonapi/node/page'),
    );
    $this->clock = new McpSealedTokenDenyAuditTestClock(
      $this->container->get('datetime.time')->getRequestTime(),
    );
  }

  /**
   * A broken dedupe store must still let the denial reach the chain.
   *
   * @covers ::record
   */
  public function testDedupeStoreFailureStillWritesRow(): void {
    $kv = $this->createMock(KeyValueExpirableFactoryInterface::class);
    $kv->method('get')->willThrowException(new \RuntimeException('kv down'));
    $this->auditor($kv)->record(McpSealedTokenDenyReason::Revoked, [
      'uid' => 5,
    ]);
    $this->assertCount(1, $this->rows());
  }

  /**
   * One reason must not hide a different reason in the same window.
   *
   * @covers ::record
   */
  public function testDistinctReasonsAreNotCollapsed(): void {
    $auditor = $this->auditor();
    $auditor->record(McpSealedTokenDenyReason::Revoked, ['uid' => 5]);
    $auditor->record(McpSealedTokenDenyReason::HashMismatch, ['uid' => 5]);
    $this->assertSame(
      ['revoked', 'hash_mismatch'],
      array_column($this->rows(), 'reason'),
    );
  }

  /**
   * One principal must not hide another principal in the same window.
   *
   * @covers ::record
   */
  public function testDistinctPrincipalsAreNotCollapsed(): void {
    $auditor = $this->auditor();
    $auditor->record(McpSealedTokenDenyReason::Revoked, ['uid' => 5]);
    $auditor->record(McpSealedTokenDenyReason::Revoked, ['uid' => 6]);
    $this->assertSame([5, 6], array_column($this->rows(), 'uid'));
  }

  /**
   * A configured window is honoured.
   *
   * @covers ::record
   */
  public function testConfiguredWindowIsHonoured(): void {
    $this->config('mcp_sentinel.settings')
      ->set('sealed_token_deny_audit_window', 300)->save();
    $this->clock->now = intdiv($this->clock->now, 300) * 300;
    $auditor = $this->auditor();
    $auditor->record(McpSealedTokenDenyReason::Revoked, ['uid' => 5]);
    $this->clock->now += 120;
    $auditor->record(McpSealedTokenDenyReason::Revoked, ['uid' => 5]);
    $this->assertCount(1, $this->rows());
    $this->assertSame(300, $this->rows()[0]['window_seconds']);
  }

  /**
   * An out-of-range window falls back to the default.
   *
   * @covers ::record
   */
  public function testOutOfRangeWindowFallsBackToDefault(): void {
    $this->config('mcp_sentinel.settings')
      ->set('sealed_token_deny_audit_window', 86400)->save();
    $this->auditor()->record(McpSealedTokenDenyReason::Revoked, [
      'uid' => 5,
    ]);
    $this->assertSame(
      McpSealedTokenDenialAuditor::DEFAULT_WINDOW,
      $this->rows()[0]['window_seconds'],
    );
  }

  /**
   * A malformed bearer is recorded by a 12-hex prefix only.
   *
   * @covers ::record
   */
  public function testMalformedRowStoresShortHashPrefixOnly(): void {
    $token = 'not-a-sealed-token-at-all';
    $manager = $this->container->get('mcp_sentinel.sealed_token_manager');
    $this->assertNull($manager->verify($token));
    $prefix = $this->rows()[0]['token_hash_prefix'] ?? '';
    $this->assertSame(
      McpSealedTokenDenialAuditor::HASH_PREFIX_LENGTH,
      strlen($prefix),
    );
    $this->assertSame(substr(hash('sha256', $token), 0, 12), $prefix);
  }

  /**
   * Varying the request path must not mint one chain row per request.
   *
   * @covers ::record
   */
  public function testDistinctPathFloodCollapses(): void {
    $this->flood(
      static fn (int $i): string => 'https://sentinel.example/probe-' . $i,
    );
    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertArrayHasKey('path', $rows[0]);
    $this->assertArrayHasKey('site', $rows[0]);
  }

  /**
   * Varying the request Host must not mint one chain row per request.
   *
   * @covers ::record
   */
  public function testDistinctHostFloodCollapses(): void {
    $this->flood(static function (int $i): string {
      return 'https://h' . $i . '.sentinel.example/jsonapi/node/page';
    });
    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertArrayHasKey('path', $rows[0]);
    $this->assertArrayHasKey('site', $rows[0]);
  }

  /**
   * Replays a forged sealed bearer against 20 request URLs in one window.
   *
   * @param callable(int): string $url
   *   Builds the request URL for attempt $i.
   */
  private function flood(callable $url): void {
    $manager = $this->container->get('mcp_sentinel.sealed_token_manager');
    $stack = $this->container->get('request_stack');
    for ($i = 0; $i < 20; $i++) {
      $this->pushRequestKeepingSession(Request::create($url($i)));
      $this->assertNull(
        $manager->verify(McpSealedTokenManager::PREFIX . 'forged.not.real'),
      );
      $stack->pop();
    }
  }

  /**
   * Builds an auditor on the test clock.
   *
   * @param \Drupal\Core\KeyValueStore\KeyValueExpirableFactoryInterface $kv
   *   Store factory. NULL uses the container store.
   */
  private function auditor(
    ?KeyValueExpirableFactoryInterface $kv = NULL,
  ): McpSealedTokenDenialAuditor {
    return new McpSealedTokenDenialAuditor(
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('config.factory'),
      $this->clock,
      $this->container->get('request_stack'),
      new TestLogger(),
      $kv ?? $this->container->get('keyvalue.expirable'),
    );
  }

  /**
   * Sealed-token denied_access metadata rows, oldest first.
   *
   * @return list<array<string, mixed>>
   *   Decoded metadata.
   */
  private function rows(): array {
    $out = [];
    $stored = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id')
      ->execute()
      ->fetchCol();
    foreach ($stored as $json) {
      $meta = json_decode((string) $json, TRUE);
      if (is_array($meta) && ($meta['tool'] ?? '') === 'sealed_token') {
        $out[] = $meta;
      }
    }
    return $out;
  }

}
