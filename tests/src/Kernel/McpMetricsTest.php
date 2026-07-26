<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for the McpMetrics dashboard-data service.
 *
 * Seeds rows directly into mcp_sentinel_audit_log and
 * mcp_sentinel_webhook_delivery, then asserts window-bounded aggregation.
 * This class runs WITHOUT the approval submodule to prove approvalSummary()
 * degrades gracefully when mcp_approval_request is undefined.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpMetrics
 */
#[Group('mcp_sentinel')]
class McpMetricsTest extends KernelTestBase {

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
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_webhook_delivery',
    ]);
  }

  /**
   * Seeds one audit_log row.
   */
  private function seedAudit(string $op, int $ts, array $meta = [], int $uid = 1): void {
    \Drupal::database()->insert('mcp_sentinel_audit_log')
      ->fields([
        'timestamp'    => $ts,
        'uid'          => $uid,
        'operation'    => $op,
        'entity_type'  => 'node',
        'bundle'       => 'article',
        'entity_id'    => '42',
        'entity_label' => 'Test node',
        'ip_address'   => '127.0.0.1',
        'user_agent'   => 'TestUA/1.0',
        'metadata'     => json_encode($meta),
        'prev_hash'    => NULL,
        'row_hash'     => NULL,
      ])
      ->execute();
  }

  /**
   * Seeds one webhook_delivery row.
   */
  private function seedDelivery(string $status, int $created, string $endpoint = 'siem'): void {
    \Drupal::database()->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'  => $endpoint,
        'event_name'   => 'mcp.entity.save',
        'payload_hash' => str_repeat('a', 64),
        'payload'      => '{}',
        'status'       => $status,
        'attempts'     => 1,
        'created'      => $created,
      ])
      ->execute();
  }

  /**
   * @covers ::auditCounts
   */
  public function testAuditCountsWithinWindow(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100);
    $this->seedAudit('denied_access', $now - 100);
    // Outside 24h and 7d but inside 30d.
    $this->seedAudit('entity_save', $now - (8 * 86400));
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $counts = $m->auditCounts('24h');
    $this->assertSame(2, $counts['total']);
    $this->assertSame(1, $counts['denied']);
    $this->assertSame(2, $m->auditCounts('7d')['total']);
    $this->assertSame(3, $m->auditCounts('30d')['total']);
  }

  /**
   * @covers ::auditCounts
   */
  public function testWindowAllowlistDefaultsToTwentyFourHours(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100);
    $this->seedAudit('entity_save', $now - (8 * 86400));
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    // A bogus window must fall back to 24h (1 row), never scan everything.
    $this->assertSame(1, $m->auditCounts('all-time')['total']);
    $this->assertSame(1, $m->auditCounts('99x')['total']);
  }

  /**
   * @covers ::allowedVsDenied
   */
  public function testAllowedVsDeniedSeries(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100);
    $this->seedAudit('entity_delete', $now - 100);
    $this->seedAudit('denied_access', $now - 100);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $series = $m->allowedVsDenied('24h');
    $this->assertSame(2, $series['allowed']);
    $this->assertSame(1, $series['denied']);
  }

  /**
   * @covers ::operationMix
   */
  public function testOperationMixCountsByOperation(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100);
    $this->seedAudit('entity_save', $now - 200);
    $this->seedAudit('denied_access', $now - 100);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $mix = $m->operationMix('24h');
    $this->assertSame(2, $mix['entity_save']);
    $this->assertSame(1, $mix['denied_access']);
  }

  /**
   * @covers ::deniedReasons
   */
  public function testDeniedReasonsGroupsByMetadataReason(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('denied_access', $now - 100, ['reason' => 'write_denied']);
    $this->seedAudit('denied_access', $now - 200, ['reason' => 'write_denied']);
    $this->seedAudit('denied_access', $now - 300, ['reason' => 'entity_type_denied']);
    // entity_save rows must not appear in denied reasons.
    $this->seedAudit('entity_save', $now - 100, ['reason' => 'noise']);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $reasons = $m->deniedReasons('24h');
    $this->assertSame(2, $reasons['write_denied']);
    $this->assertSame(1, $reasons['entity_type_denied']);
    $this->assertArrayNotHasKey('noise', $reasons);
  }

  /**
   * @covers ::deniedReasons
   *
   * rate_limit_exceeded rows carry no 'reason' metadata key; they must appear
   * under their operation string ('rate_limit_exceeded'), not 'unspecified'.
   * Both denied_access (with reason) and rate_limit_exceeded (no reason) must
   * be present — the query must use IN (DENIED_OPERATIONS).
   */
  public function testDeniedReasonsIncludesRateLimitExceeded(): void {
    $now = \Drupal::time()->getRequestTime();
    // denied_access row WITH an explicit reason key.
    $this->seedAudit('denied_access', $now - 100, ['reason' => 'write_denied']);
    // rate_limit_exceeded row — metadata does NOT carry a 'reason' key; it
    // carries the tool name as per McpEntityToolTrait::checkRateLimit().
    $this->seedAudit('rate_limit_exceeded', $now - 200, ['tool' => 'mcp_node_ops']);
    $this->seedAudit('rate_limit_exceeded', $now - 300, ['tool' => 'mcp_node_ops']);
    // entity_save must be invisible.
    $this->seedAudit('entity_save', $now - 100, []);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $reasons = $m->deniedReasons('24h');
    // Policy denial labelled by its metadata reason key.
    $this->assertSame(1, $reasons['write_denied']);
    // Rate-limit denials labelled by operation name (no 'reason' key present).
    $this->assertSame(2, $reasons['rate_limit_exceeded']);
    // entity_save must not appear.
    $this->assertArrayNotHasKey('entity_save', $reasons);
    // No 'unspecified' bucket — operation name fallback is used instead.
    $this->assertArrayNotHasKey('unspecified', $reasons);
  }

  /**
   * @covers ::topAgents
   */
  public function testTopAgentsGroupsByUid(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100, [], 5);
    $this->seedAudit('entity_save', $now - 200, [], 5);
    $this->seedAudit('denied_access', $now - 100, [], 5);
    $this->seedAudit('entity_save', $now - 100, [], 7);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $agents = $m->topAgents('24h', 5);
    // Highest-volume agent first.
    $this->assertSame(5, $agents[0]['uid']);
    $this->assertSame(3, $agents[0]['total']);
    $this->assertSame(1, $agents[0]['denied']);
    $this->assertSame(7, $agents[1]['uid']);
    $this->assertSame(1, $agents[1]['total']);
  }

  /**
   * @covers ::auditTimeSeries
   */
  public function testAuditTimeSeriesBucketsAndCounts(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100);
    $this->seedAudit('entity_save', $now - 200);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $series = $m->auditTimeSeries('24h');
    $this->assertNotEmpty($series);
    $this->assertSame(2, array_sum(array_column($series, 'count')));
    // Each bucket carries an 'anomaly' flag; none fired here.
    $bucket = reset($series);
    $this->assertFalse($bucket['anomaly']);
  }

  /**
   * @covers ::webhookHealth
   */
  public function testWebhookHealthSuccessRate(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedDelivery('sent', $now - 100);
    $this->seedDelivery('sent', $now - 200);
    $this->seedDelivery('failed', $now - 100);
    $this->seedDelivery('failed_key', $now - 100);
    $this->seedDelivery('pending', $now - 100);
    // Outside window: ignored.
    $this->seedDelivery('sent', $now - (8 * 86400));
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $health = $m->webhookHealth('24h');
    $this->assertSame(2, $health['sent']);
    $this->assertSame(2, $health['failed']);
    $this->assertSame(1, $health['pending']);
    $this->assertSame(5, $health['total']);
    // Success rate = sent / (sent + terminal failures), excludes pending.
    $this->assertEqualsWithDelta(50.0, $health['success_rate'], 0.1);
  }

  /**
   * @covers ::approvalSummary
   */
  public function testApprovalSummaryNullSafeWhenSubmoduleAbsent(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $this->assertSame(
      ['pending' => 0, 'oldest_age' => NULL, 'available' => FALSE],
      $m->approvalSummary(),
    );
  }

  /**
   * @covers ::statusSummary
   */
  public function testStatusSummaryReflectsConfig(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $status = $m->statusSummary();
    $this->assertTrue($status['governed']);
    // The module ships a 'default' policy profile on install.
    $this->assertSame(1, $status['profile_count']);

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', FALSE)->save();
    // Rebuild service to clear the per-request static cache.
    $this->container->set('mcp_sentinel.metrics', NULL);
    $status = \Drupal::service('mcp_sentinel.metrics')->statusSummary();
    $this->assertFalse($status['governed']);
  }

  /**
   * @covers ::activeControls
   */
  public function testActiveControlsReflectsConfig(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('audit_hash_key', 'some_key')
      ->set('siem_enabled', TRUE)
      ->set('dlp_enabled', TRUE)
      ->save();
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $controls = $m->activeControls();
    $this->assertTrue($controls['hash_chain']);
    $this->assertTrue($controls['siem']);
    $this->assertTrue($controls['dlp']);
    $this->assertFalse($controls['encryption']);
    $this->assertFalse($controls['approvals']);
    $this->assertArrayHasKey('rate_limit', $controls);
    $this->assertArrayHasKey('ip_allowlist', $controls);
  }

  /**
   * @covers ::anomalySummary
   */
  public function testAnomalySummaryReadsStateAndConfig(): void {
    $now = \Drupal::time()->getRequestTime();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [
        ['id' => 'r1', 'enabled' => TRUE, 'operation_pattern' => 'x', 'window_seconds' => 60, 'threshold' => 1],
        ['id' => 'r2', 'enabled' => FALSE, 'operation_pattern' => 'y', 'window_seconds' => 60, 'threshold' => 1],
      ])->save();
    \Drupal::state()->set('mcp_sentinel.anomaly_last_alert.r1', $now - 60);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $summary = $m->anomalySummary('24h');
    $this->assertSame(1, $summary['enabled_rules']);
    $this->assertSame(1, $summary['alerts']);
  }

  /**
   * @covers ::chainIntegrity
   */
  public function testChainIntegrityReadsStoredVerifyWithoutRerunning(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->seedAudit('entity_save', $now - 100);
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => TRUE,
      'broken_at' => NULL,
      'time' => $now - 10,
    ]);
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $chain = $m->chainIntegrity();
    $this->assertTrue($chain['ok']);
    $this->assertNull($chain['broken_at']);
    $this->assertSame(1, $chain['rows']);
    $this->assertSame($now - 10, $chain['verified_at']);
  }

  /**
   * @covers ::chainIntegrity
   */
  public function testChainIntegrityNeverVerifiedIsNullSafe(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $m */
    $m = \Drupal::service('mcp_sentinel.metrics');
    $chain = $m->chainIntegrity();
    $this->assertNull($chain['ok']);
    $this->assertNull($chain['verified_at']);
    $this->assertSame(0, $chain['rows']);
  }

}
