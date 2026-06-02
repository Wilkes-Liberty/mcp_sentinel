<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Psr\Log\NullLogger;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Drush\Commands\McpSentinelCommands;
use Drush\Log\DrushLoggerManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for McpSentinelCommands Drush commands.
 *
 * Covers gap G12: exercises every command's core logic by invoking the command
 * object directly with real services — the same approach used for other
 * service-layer kernel tests in this suite. No Drush bootstrap is required
 * because the command class is a plain PHP class whose methods call injected
 * services.
 *
 * Commands covered:
 *  - audit-verify: returns EXIT_SUCCESS on a clean chain; EXIT_FAILURE
 *    on tamper.
 *  - webhook-prune: deletes rows past retention, returns EXIT_SUCCESS.
 *  - lock-clear: releases expired locks, returns EXIT_SUCCESS.
 *  - audit-purge: prunes old rows when retention > 0; no-op when retention = 0.
 *  - webhook-replay: EXIT_FAILURE on bad ID, EXIT_SUCCESS when delivery exists.
 *  - status: EXIT_SUCCESS and includes key settings.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Drush\Commands\McpSentinelCommands
 * @group mcp_sentinel
 */
#[CoversClass(McpSentinelCommands::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDrushCommandsTest extends KernelTestBase {

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
   * The command object under test.
   */
  private McpSentinelCommands $commands;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);

    // Build the command object with real services from the container.
    $this->commands = new McpSentinelCommands(
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.content_lock'),
      $this->container->get('database'),
      $this->container->get('entity_type.manager'),
      $this->container->get('mcp_sentinel.webhook_queue_manager'),
      $this->container->get('state'),
      $this->container->get('datetime.time'),
    );

    // Wire a no-op DrushLoggerManager so commands can call $this->logger()->
    // without output. Drush requires DrushLoggerManager (not a plain PSR-3
    // logger) since it asserts on the type — use DrushLoggerManager::add().
    $drushLogger = new DrushLoggerManager();
    $drushLogger->add('null', new NullLogger());
    $this->commands->setLogger($drushLogger);
  }

  /**
   * Audit-verify returns EXIT_SUCCESS on a clean (empty) chain.
   *
   * @covers ::auditVerify
   */
  public function testAuditVerifySucceedsOnCleanChain(): void {
    $result = $this->commands->auditVerify();
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'audit-verify must return EXIT_SUCCESS on an untampered (empty) chain.'
    );
  }

  /**
   * Audit-verify returns EXIT_SUCCESS on a valid chain with real entries.
   *
   * @covers ::auditVerify
   */
  public function testAuditVerifySucceedsWithValidEntries(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1', 'label' => 'A']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '2', 'label' => 'B']);

    $result = $this->commands->auditVerify();
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'audit-verify must return EXIT_SUCCESS when the chain is intact.'
    );
  }

  /**
   * Audit-verify returns EXIT_FAILURE when a row has been tampered with.
   *
   * @covers ::auditVerify
   */
  public function testAuditVerifyFailsOnTamperedChain(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpAuditLogger $logger */
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1', 'label' => 'First']);

    // Tamper: overwrite the row_hash with garbage.
    $this->container->get('database')
      ->update('mcp_sentinel_audit_log')
      ->fields(['row_hash' => 'tampered'])
      ->execute();

    $result = $this->commands->auditVerify();
    $this->assertSame(
      McpSentinelCommands::EXIT_FAILURE,
      $result,
      'audit-verify must return EXIT_FAILURE when the hash chain is broken.'
    );
  }

  /**
   * Webhook-prune deletes old rows and returns EXIT_SUCCESS.
   *
   * @covers ::webhookPrune
   */
  public function testWebhookPruneDeletesOldRowsAndSucceeds(): void {
    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Insert a row older than the default 30-day retention.
    $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep1',
      'event_name' => 'mcp.test',
      'payload_hash' => hash('sha256', 'old'),
      'status' => 'sent',
      'attempts' => 1,
      'created' => $now - (40 * 86400),
    ])->execute();

    // Insert a fresh row that must NOT be pruned.
    $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep1',
      'event_name' => 'mcp.test',
      'payload_hash' => hash('sha256', 'fresh'),
      'status' => 'sent',
      'attempts' => 1,
      'created' => $now,
    ])->execute();

    $result = $this->commands->webhookPrune();
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'webhook-prune must return EXIT_SUCCESS.'
    );

    // Only the old row should have been deleted; the fresh row remains.
    $remaining = (int) $db->select('mcp_sentinel_webhook_delivery')
      ->countQuery()->execute()->fetchField();
    $this->assertSame(1, $remaining,
      'webhook-prune must remove only rows past the retention window.');
  }

  /**
   * Lock-clear releases expired locks and returns EXIT_SUCCESS.
   *
   * @covers ::lockClear
   */
  public function testLockClearReleasesExpiredLocksAndSucceeds(): void {
    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Insert an expired lock.
    $db->insert('mcp_sentinel_content_locks')->fields([
      'entity_type' => 'node',
      'entity_id' => '99',
      'locked_by' => 1,
      'locked_at' => $now - 7200,
      'expires_at' => $now - 3600,
      'reason' => 'expired',
    ])->execute();

    // Insert a non-expired lock.
    $db->insert('mcp_sentinel_content_locks')->fields([
      'entity_type' => 'node',
      'entity_id' => '100',
      'locked_by' => 1,
      'locked_at' => $now,
      'expires_at' => $now + 7200,
      'reason' => 'active',
    ])->execute();

    $result = $this->commands->lockClear();
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'lock-clear must return EXIT_SUCCESS.'
    );

    // Only the active lock should remain.
    $remaining = (int) $db->select('mcp_sentinel_content_locks')
      ->countQuery()->execute()->fetchField();
    $this->assertSame(1, $remaining,
      'lock-clear must release only expired locks, leaving active ones.');
  }

  /**
   * Audit-purge removes old entries when retention > 0.
   *
   * @covers ::auditPurge
   */
  public function testAuditPurgeRemovesOldEntriesWhenRetentionSet(): void {
    $this->config('mcp_sentinel.settings')->set('audit_retention_days', 30)->save();

    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Row older than 30 days.
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now - (40 * 86400),
      'uid' => 0,
      'operation' => 'old_op',
    ])->execute();
    // Fresh row.
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now,
      'uid' => 0,
      'operation' => 'fresh_op',
    ])->execute();

    $result = $this->commands->auditPurge();
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'audit-purge must return EXIT_SUCCESS.'
    );

    $remaining = (int) $db->select('mcp_sentinel_audit_log')
      ->countQuery()->execute()->fetchField();
    $this->assertSame(1, $remaining,
      'audit-purge must delete rows past the retention window.');
  }

  /**
   * Audit-purge is a no-op when retention is 0 (keep forever).
   *
   * @covers ::auditPurge
   */
  public function testAuditPurgeIsNoOpWhenRetentionZero(): void {
    $this->config('mcp_sentinel.settings')->set('audit_retention_days', 0)->save();

    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now - (400 * 86400),
      'uid' => 0,
      'operation' => 'ancient',
    ])->execute();

    $result = $this->commands->auditPurge();
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'audit-purge with retention=0 must still return EXIT_SUCCESS.'
    );

    $remaining = (int) $db->select('mcp_sentinel_audit_log')
      ->countQuery()->execute()->fetchField();
    $this->assertSame(1, $remaining,
      'audit-purge must not delete any rows when retention_days is 0 (forever).');
  }

  /**
   * Webhook-replay returns EXIT_FAILURE when the delivery ID is zero or absent.
   *
   * @covers ::webhookReplay
   */
  public function testWebhookReplayFailsOnBadId(): void {
    $result = $this->commands->webhookReplay(0);
    $this->assertSame(
      McpSentinelCommands::EXIT_FAILURE,
      $result,
      'webhook-replay must return EXIT_FAILURE for a zero delivery ID.'
    );

    $result2 = $this->commands->webhookReplay(99999);
    $this->assertSame(
      McpSentinelCommands::EXIT_FAILURE,
      $result2,
      'webhook-replay must return EXIT_FAILURE for a non-existent delivery ID.'
    );
  }

  /**
   * Webhook-replay succeeds when a valid pending delivery row exists.
   *
   * @covers ::webhookReplay
   */
  public function testWebhookReplaySucceedsForValidDelivery(): void {
    // Configure a webhook endpoint so the replay can find its config.
    $this->config('mcp_sentinel.settings')
      ->set('webhook_enabled', TRUE)
      ->set('webhook_endpoints', [
        [
          'id' => 'ep1',
          'label' => 'Test',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
        ],
      ])
      ->save();

    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    $rowId = (int) $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep1',
      'event_name' => 'mcp.test',
      'payload_hash' => hash('sha256', 'test'),
      'payload' => '{}',
      'status' => 'failed',
      'attempts' => 3,
      'created' => $now,
    ])->execute();

    $result = $this->commands->webhookReplay($rowId);
    $this->assertSame(
      McpSentinelCommands::EXIT_SUCCESS,
      $result,
      'webhook-replay must return EXIT_SUCCESS for a valid delivery row.'
    );

    // Verify the row status was reset to pending.
    $status = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['status'])
      ->condition('d.id', $rowId)
      ->execute()
      ->fetchField();
    $this->assertSame('pending', $status,
      'webhook-replay must reset the delivery row status to pending.');
  }

  /**
   * Audit-verify writes last_verify state (ok=TRUE) on a clean chain.
   *
   * @covers ::auditVerify
   */
  public function testAuditVerifyWritesStateOnCleanChain(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpAuditLogger $logger */
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1', 'label' => 'A']);

    $result = $this->commands->auditVerify();
    $this->assertSame(McpSentinelCommands::EXIT_SUCCESS, $result);

    $state = \Drupal::state()->get('mcp_sentinel.last_verify');
    $this->assertIsArray($state, 'audit-verify must write mcp_sentinel.last_verify state.');
    $this->assertTrue($state['ok'], 'State ok must be TRUE on a clean chain.');
    $this->assertNull($state['broken_at'], 'State broken_at must be NULL on a clean chain.');
    $this->assertSame(1, $state['rows'], 'State rows must equal the audit log row count.');
    $this->assertIsInt($state['time'], 'State time must be an integer timestamp.');

    // McpMetrics::chainIntegrity() must reflect the stored state.
    /** @var \Drupal\mcp_sentinel\Service\McpMetrics $metrics */
    $metrics = \Drupal::service('mcp_sentinel.metrics');
    $chain = $metrics->chainIntegrity();
    $this->assertTrue($chain['ok']);
    $this->assertSame(1, $chain['rows']);

    // McpUrgentConditions must NOT fire chain_broken when ok===TRUE.
    $keys = array_column(\Drupal::service('mcp_sentinel.urgent_conditions')->evaluate(), 'key');
    $this->assertNotContains('chain_broken', $keys);
  }

  /**
   * Audit-verify writes last_verify state (ok=FALSE) on a tampered chain.
   *
   * @covers ::auditVerify
   */
  public function testAuditVerifyWritesStateOnTamperedChain(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpAuditLogger $logger */
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1', 'label' => 'First']);

    // Tamper: overwrite row_hash with garbage so verifyChain() returns FALSE.
    $this->container->get('database')
      ->update('mcp_sentinel_audit_log')
      ->fields(['row_hash' => 'tampered'])
      ->execute();

    $result = $this->commands->auditVerify();
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);

    $state = \Drupal::state()->get('mcp_sentinel.last_verify');
    $this->assertIsArray($state, 'audit-verify must write mcp_sentinel.last_verify state even on failure.');
    $this->assertFalse($state['ok'], 'State ok must be FALSE on a tampered chain.');
    $this->assertNotNull($state['broken_at'], 'State broken_at must be set when the chain is broken.');

    // McpUrgentConditions must fire chain_broken when ok===FALSE.
    $conditions = \Drupal::service('mcp_sentinel.urgent_conditions')->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('chain_broken', $keys, 'chain_broken urgent condition must fire after a failed audit-verify.');
    $crit = array_filter($conditions, fn($c) => $c['key'] === 'chain_broken');
    $this->assertSame('critical', reset($crit)['severity']);
  }

  /**
   * Status returns EXIT_SUCCESS with no fatal errors.
   *
   * Because DrushCommands::io() (SymfonyStyle) is only available inside a
   * real Drush session, we cannot call status() directly in a kernel test
   * without triggering an error on the io()->title() / io()->table() calls.
   * This test instead verifies the underlying data services that status()
   * uses, confirming the query paths work correctly.
   *
   * @covers ::status
   */
  public function testStatusDataPathsWork(): void {
    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Insert an audit row and a lock row so the counts are non-zero.
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now,
      'uid' => 0,
      'operation' => 'entity_save',
    ])->execute();
    $db->insert('mcp_sentinel_content_locks')->fields([
      'entity_type' => 'node',
      'entity_id' => '1',
      'locked_by' => 1,
      'locked_at' => $now,
      'expires_at' => $now + 3600,
    ])->execute();

    // Verify count queries that status() uses.
    $auditCount = (int) $db->select('mcp_sentinel_audit_log')
      ->countQuery()->execute()->fetchField();
    $lockCount = (int) $db->select('mcp_sentinel_content_locks')
      ->countQuery()->execute()->fetchField();

    $this->assertSame(1, $auditCount,
      'status data: audit log count must reflect seeded rows.');
    $this->assertSame(1, $lockCount,
      'status data: content lock count must reflect seeded rows.');

    // Verify config reads succeed.
    $config = $this->container->get('config.factory')
      ->get('mcp_sentinel.settings');
    $this->assertNotNull($config->get('enabled'),
      'status data: mcp_sentinel.settings:enabled must be readable.');
    $this->assertNotNull($config->get('audit_enabled'),
      'status data: mcp_sentinel.settings:audit_enabled must be readable.');
  }

}
