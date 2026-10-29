<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\key\Entity\Key;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Psr\Log\AbstractLogger;
use Psr\Log\NullLogger;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Drush\Commands\McpSentinelCommands;
use Drupal\mcp_sentinel\Service\McpAnomalyEvidence;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drush\Log\DrushLoggerManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\HttpFoundation\Request;

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
 *  - audit-purge: asks the chain to prune when retention > 0; no-op when
 *    retention = 0. Audit Chain 1.8.0 refuses the delete and keeps the rows.
 *  - webhook-replay: EXIT_FAILURE on bad ID, EXIT_SUCCESS when delivery exists.
 *  - status: EXIT_SUCCESS and includes key settings.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Drush\Commands\McpSentinelCommands
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSentinelCommands::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDrushCommandsTest extends KernelTestBase {

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
    'audit_chain',
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

    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', [
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
      $this->container->get('mcp_sentinel.urgent_conditions'),
      $this->container->get('mcp_sentinel.role_assertions'),
      $this->container->get('mcp_sentinel.governance_readiness'),
      $this->container->get('mcp_sentinel.install_verifier'),
      $this->container->get('mcp_sentinel.anomaly_evidence'),
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
      ->update('audit_chain_log')
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
   * Audit-purge still succeeds when retention > 0, but the chain keeps rows.
   *
   * @covers ::auditPurge
   */
  public function testAuditPurgeRemovesOldEntriesWhenRetentionSet(): void {
    $this->config('mcp_sentinel.settings')->set('audit_retention_days', 30)->save();

    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Row older than 30 days.
    $db->insert('audit_chain_log')->fields([
      'timestamp' => $now - (40 * 86400),
      'uid' => 0,
      'operation' => 'old_op',
    ])->execute();
    // Fresh row.
    $db->insert('audit_chain_log')->fields([
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

    $remaining = (int) $db->select('audit_chain_log')
      ->countQuery()->execute()->fetchField();
    $this->assertSame(2, $remaining,
      'audit-purge must keep rows: Audit Chain 1.8.0 refuses per-channel prune.');
    $this->assertTrue(
      (bool) $this->container->get('state')->get('audit_chain.retention_refused'),
      'Expired rows must surface as a retention refusal, not a silent keep.',
    );
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

    $db->insert('audit_chain_log')->fields([
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

    $remaining = (int) $db->select('audit_chain_log')
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
      'event_name' => 'mcp.entity.presave',
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
   * Webhook-replay refuses a stored unknown event_name.
   *
   * @covers ::webhookReplay
   */
  public function testWebhookReplayRefusesUnknownEventName(): void {
    $this->config('mcp_sentinel.settings')
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
      'event_name' => 'mcp.not.a.live.event',
      'payload_hash' => hash('sha256', 'test'),
      'payload' => '{}',
      'status' => 'failed',
      'attempts' => 1,
      'created' => $now,
    ])->execute();

    $result = $this->commands->webhookReplay($rowId);
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);
    $status = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['status'])
      ->condition('d.id', $rowId)
      ->execute()
      ->fetchField();
    $this->assertSame(McpWebhookQueueManager::STATUS_FAILED, $status);
  }

  /**
   * Webhook-replay of a held unknown name names the status, not a refusal.
   *
   * @covers ::webhookReplay
   */
  public function testWebhookReplayHeldUnknownEventNameNamesStatus(): void {
    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();
    $rowId = (int) $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep1',
      'event_name' => 'mcp.not.a.live.event',
      'payload_hash' => hash('sha256', 'test'),
      'payload' => '{}',
      'status' => McpWebhookQueueManager::STATUS_HELD,
      'attempts' => 1,
      'created' => $now,
    ])->execute();

    $spy = new class() extends AbstractLogger {

      /**
       * Captured log records.
       *
       * @var array<int, array{0: string, 1: string}>
       */
      public array $records = [];

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->records[] = [(string) $level, (string) $message];
      }

    };
    $drushLogger = new DrushLoggerManager();
    $drushLogger->add('spy', $spy);
    $this->commands->setLogger($drushLogger);

    $result = $this->commands->webhookReplay($rowId);
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);
    $messages = array_column($spy->records, 1);
    $this->assertContains(
      sprintf(
        'Delivery %d could not be replayed (%s).',
        $rowId,
        McpWebhookQueueManager::STATUS_HELD,
      ),
      $messages,
    );
    foreach ($messages as $message) {
      $this->assertStringNotContainsString('was refused', $message);
    }
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
    $this->assertNull($state['reason'], 'A clean chain stores no failure reason.');
    $this->assertFalse($state['unsigned_prefix'], 'A clean chain is not an unsigned prefix.');
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
      ->update('audit_chain_log')
      ->fields(['row_hash' => 'tampered'])
      ->execute();

    $result = $this->commands->auditVerify();
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);

    $state = \Drupal::state()->get('mcp_sentinel.last_verify');
    $this->assertIsArray($state, 'audit-verify must write mcp_sentinel.last_verify state even on failure.');
    $this->assertFalse($state['ok'], 'State ok must be FALSE on a tampered chain.');
    $this->assertNotNull($state['broken_at'], 'State broken_at must be set when the chain is broken.');
    $this->assertSame('tampered', $state['reason']);
    $this->assertFalse($state['unsigned_prefix'], 'Tampering must not be stored as the unsigned prefix.');

    // McpUrgentConditions must fire chain_broken when ok===FALSE.
    $conditions = \Drupal::service('mcp_sentinel.urgent_conditions')->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('chain_broken', $keys, 'chain_broken urgent condition must fire after a failed audit-verify.');
    $crit = array_filter($conditions, fn($c) => $c['key'] === 'chain_broken');
    $this->assertSame('critical', reset($crit)['severity']);
  }

  /**
   * A leading unsigned prefix fails the command and is stored as a warning.
   *
   * The prefix is not re-signed and is not deleted. Whole-history
   * verification stays unsuccessful, and the dashboard must not call it
   * tampering.
   *
   * @covers ::auditVerify
   */
  public function testAuditVerifyStoresUnsignedPrefixAsWarning(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpAuditLogger $logger */
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => 'legacy', 'label' => 'Unsigned']);

    Key::create([
      'id' => 'mcp_prefix_key',
      'label' => 'MCP prefix key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'prefix-successor-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'mcp_prefix_key')
      ->save();
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => 'successor', 'label' => 'Signed']);

    $spy = new class() extends AbstractLogger {

      /**
       * Captured log records.
       *
       * @var array<int, array{0: string, 1: string}>
       */
      public array $records = [];

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->records[] = [(string) $level, (string) $message];
      }

    };
    $drushLogger = new DrushLoggerManager();
    $drushLogger->add('spy', $spy);
    $this->commands->setLogger($drushLogger);

    $result = $this->commands->auditVerify();
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);

    $state = \Drupal::state()->get('mcp_sentinel.last_verify');
    $this->assertIsArray($state);
    $this->assertFalse($state['ok']);
    $this->assertNull($state['broken_at']);
    $this->assertSame('written_unkeyed', $state['reason']);
    $this->assertTrue($state['unsigned_prefix']);
    $this->assertSame(2, $state['rows']);

    $conditions = \Drupal::service('mcp_sentinel.urgent_conditions')->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('unsigned_prefix', $keys);
    $this->assertNotContains('chain_broken', $keys);
    $prefix = array_filter($conditions, fn($c) => $c['key'] === 'unsigned_prefix');
    $this->assertSame('warning', reset($prefix)['severity']);

    $messages = implode("\n", array_column($spy->records, 1));
    $this->assertStringContainsString('unkeyed SHA-256', $messages);
    $this->assertStringNotContainsString('tampered', strtolower($messages));
  }

  /**
   * Status data paths, including shared readiness, work without fatal errors.
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
    $db->insert('audit_chain_log')->fields([
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
    $auditCount = (int) $db->select('audit_chain_log')
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

    // Status reports enabled webhook_endpoints, not leftover webhook_enabled.
    $this->config('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'siem',
          'enabled' => TRUE,
        ],
        [
          'id' => 'disabled',
          'enabled' => FALSE,
        ],
      ])
      ->save();
    $endpoints = (array) $this->container->get('config.factory')
      ->get('mcp_sentinel.settings')
      ->get('webhook_endpoints');
    $enabled_ids = [];
    foreach ($endpoints as $endpoint) {
      if (!empty($endpoint['enabled'])) {
        $enabled_ids[] = (string) ($endpoint['id'] ?? '');
      }
    }
    $this->assertSame(['siem'], $enabled_ids,
      'status data: enabled webhook_endpoints ids ignore leftover webhook_enabled.');

    // The base-only kernel fixture is intentionally not production-ready:
    // status must consume this same typed result rather than inventing a
    // separate or more permissive health claim.
    $contract = $this->container
      ->get('mcp_sentinel.governance_readiness')
      ->contractStatus();
    $this->assertFalse($contract->isReady());
    $this->assertNotNull($contract->reason());
  }

  /**
   * Denied-access summary groups rows and audits the operator read.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryGroupsAndAudits(): void {
    $this->config('system.site')->set('name', 'Example MCP site')->save();
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'REMOTE_ADDR' => '192.0.2.10',
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
    ]);
    $this->pushRequestKeepingSession($request);
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'reason' => 'missing_bearer',
      'client_id' => 'example-client',
      'token' => 'secret-token-value',
      'authorization' => 'Bearer secret-token-value',
      'payload' => '{"password":"secret-token-value"}',
    ]);

    $output = new BufferedOutput();
    $this->commands->setOutput($output);
    $result = $this->commands->deniedAccessSummary([
      'window-seconds' => 300,
      'top' => 8,
      'json' => FALSE,
    ]);
    $this->assertSame(McpSentinelCommands::EXIT_SUCCESS, $result);
    $text = $output->fetch();
    $this->assertStringContainsString('Site: Example MCP site', $text);
    $this->assertStringContainsString('Host:', $text);
    $this->assertStringContainsString('Environment:', $text);
    $this->assertStringContainsString('Window: 300 s', $text);
    $this->assertStringContainsString('client=example-client', $text);
    $this->assertStringContainsString('origin=https://client.example.test', $text);
    $this->assertStringContainsString('ip=192.0.2.10', $text);
    $this->assertStringContainsString('reason=missing_bearer', $text);
    $this->assertStringNotContainsString('secret-token-value', $text);
    $this->assertStringNotContainsString('Bearer secret-token-value', $text);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('l.operation', McpAnomalyEvidence::AUDIT_DENIED_ACCESS_SUMMARY)
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row, 'The operator read must be audited.');
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame(300, $metadata['window_seconds']);
    $this->assertSame('read', $metadata['outcome']);
    $this->assertSame(1, $metadata['count']);
    $this->assertStringNotContainsString('secret-token-value', (string) $row['metadata']);
  }

  /**
   * Invalid window is audited and prints no summary.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryRefusesNonPositiveWindow(): void {
    $output = new BufferedOutput();
    $this->commands->setOutput($output);
    $result = $this->commands->deniedAccessSummary([
      'window-seconds' => 0,
      'top' => 8,
      'json' => FALSE,
    ]);
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);
    $this->assertSame('', $output->fetch());

    $metadata = json_decode((string) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpAnomalyEvidence::AUDIT_DENIED_ACCESS_SUMMARY)
      ->execute()
      ->fetchField(), TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('invalid_window', $metadata['outcome']);
  }

  /**
   * Negative and over-cap windows are refused and print nothing.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryRefusesNegativeAndOverCapWindow(): void {
    foreach ([-1, McpAnomalyEvidence::WINDOW_MAX + 1] as $window) {
      $output = new BufferedOutput();
      $this->commands->setOutput($output);
      $result = $this->commands->deniedAccessSummary([
        'window-seconds' => $window,
        'top' => 8,
        'json' => FALSE,
      ]);
      $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);
      $this->assertSame('', $output->fetch());
    }

    $outcomes = [];
    $rows = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpAnomalyEvidence::AUDIT_DENIED_ACCESS_SUMMARY)
      ->execute();
    foreach ($rows as $row) {
      $metadata = json_decode((string) $row->metadata, TRUE);
      $outcomes[] = is_array($metadata) ? ($metadata['outcome'] ?? NULL) : NULL;
    }
    $this->assertSame(['invalid_window', 'invalid_window'], $outcomes);
  }

  /**
   * A --top value above 32 is refused as invalid_top.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryRefusesOverCapTop(): void {
    $output = new BufferedOutput();
    $this->commands->setOutput($output);
    $result = $this->commands->deniedAccessSummary([
      'window-seconds' => 300,
      'top' => McpAnomalyEvidence::TOP_MAX + 1,
      'json' => FALSE,
    ]);
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);
    $this->assertSame('', $output->fetch());

    $metadata = json_decode((string) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpAnomalyEvidence::AUDIT_DENIED_ACCESS_SUMMARY)
      ->execute()
      ->fetchField(), TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('invalid_top', $metadata['outcome']);
  }

  /**
   * Audit-chain failure prints nothing in text or JSON.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryPrintsNothingWhenAuditFails(): void {
    $chain = $this->createMock(AuditChainLoggerInterface::class);
    $chain->method('log')->willThrowException(new \RuntimeException('chain down'));
    $failingLogger = new McpAuditLogger(
      $this->container->get('config.factory'),
      $this->container->get('request_stack'),
      $chain,
      $this->container->get('mcp_sentinel.dlp'),
      $this->container->get('database'),
    );
    $evidence = new McpAnomalyEvidence(
      $this->container->get('database'),
      $this->container->get('config.factory'),
      $this->container->get('settings'),
      $this->container->get('request_stack'),
      $failingLogger,
      $this->container->get('mcp_sentinel.dlp'),
      $this->container->get('mcp_sentinel.anomaly_detector'),
      $this->container->get('datetime.time'),
    );
    $commands = $this->buildCommands($evidence);

    foreach ([FALSE, TRUE] as $json) {
      $output = new BufferedOutput();
      $commands->setOutput($output);
      $result = $commands->deniedAccessSummary([
        'window-seconds' => 300,
        'top' => 8,
        'json' => $json,
      ]);
      $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $result);
      $this->assertSame('', $output->fetch());
    }

    $count = (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', McpAnomalyEvidence::AUDIT_DENIED_ACCESS_SUMMARY)
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(0, $count);
  }

  /**
   * JSON output decodes to an array, including a multibyte Origin.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryJsonDecodesWithMultibyteOrigin(): void {
    $origin = 'https://x' . str_repeat("\u{00E9}", 95);
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'reason' => 'missing_bearer',
      'client_id' => 'mb-client',
      'http_origin' => $origin,
    ]);

    $output = new BufferedOutput();
    $this->commands->setOutput($output);
    $result = $this->commands->deniedAccessSummary([
      'window-seconds' => 300,
      'top' => 8,
      'json' => TRUE,
    ]);
    $this->assertSame(McpSentinelCommands::EXIT_SUCCESS, $result);
    $decoded = json_decode($output->fetch(), TRUE);
    $this->assertIsArray($decoded);
    $this->assertArrayHasKey('groups', $decoded);
    $this->assertArrayHasKey('count', $decoded);
    $this->assertArrayHasKey('scanned', $decoded);
    $this->assertArrayHasKey('truncated', $decoded);
  }

  /**
   * Truncated scans print Count: N (scanned M, truncated).
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryPrintsTruncation(): void {
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'REMOTE_ADDR' => '192.0.2.10',
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
    ]);
    $this->pushRequestKeepingSession($request);
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    for ($i = 0; $i < 3; $i++) {
      $logger->logAlways('denied_access', [
        'reason' => 'missing_bearer',
        'client_id' => 'example-client',
      ]);
    }
    $evidence = new McpAnomalyEvidence(
      $this->container->get('database'),
      $this->container->get('config.factory'),
      $this->container->get('settings'),
      $this->container->get('request_stack'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.dlp'),
      $this->container->get('mcp_sentinel.anomaly_detector'),
      $this->container->get('datetime.time'),
      2,
    );
    $commands = $this->buildCommands($evidence);
    $output = new BufferedOutput();
    $commands->setOutput($output);
    $result = $commands->deniedAccessSummary([
      'window-seconds' => 300,
      'top' => 8,
      'json' => FALSE,
    ]);
    $this->assertSame(McpSentinelCommands::EXIT_SUCCESS, $result);
    $this->assertStringContainsString('Count: 3 (scanned 2, truncated)', $output->fetch());
  }

  /**
   * Builds a command object with an injected evidence service.
   */
  private function buildCommands(McpAnomalyEvidence $evidence): McpSentinelCommands {
    $commands = new McpSentinelCommands(
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.content_lock'),
      $this->container->get('database'),
      $this->container->get('entity_type.manager'),
      $this->container->get('mcp_sentinel.webhook_queue_manager'),
      $this->container->get('state'),
      $this->container->get('datetime.time'),
      $this->container->get('mcp_sentinel.urgent_conditions'),
      $this->container->get('mcp_sentinel.role_assertions'),
      $this->container->get('mcp_sentinel.governance_readiness'),
      $this->container->get('mcp_sentinel.install_verifier'),
      $evidence,
    );
    $drushLogger = new DrushLoggerManager();
    $drushLogger->add('null', new NullLogger());
    $commands->setLogger($drushLogger);
    return $commands;
  }

}
