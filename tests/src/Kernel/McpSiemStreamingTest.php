<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use ColinODell\PsrTestLogger\TestLogger;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for SIEM streaming via the audit_chain stream channel.
 *
 * Audit Chain 1.12.x streams audit_chain_event on
 * logger.channel.audit_chain. 1.13.0 moved it to audit_chain.stream so
 * the record does not fan out to dblog. 1.13.1 restored
 * logger.channel.audit_chain as the default and uses audit_chain.stream
 * only when stream_exclude_dblog is set. The spy follows whichever
 * service the installed chain actually uses.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSiemStreamingTest extends KernelTestBase {

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installConfig(['audit_chain', 'mcp_sentinel']);
  }

  /**
   * Live SIEM records land on the chain's stream channel.
   *
   * Exactly one channel receives the record: the one siemChannelId()
   * resolves for the installed Audit Chain. A build that writes to the
   * other channel fails this test.
   */
  public function testLiveSiemChannelIsAuditChain(): void {
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->save();

    $expected = $this->siemChannelId();
    $expected_spy = new TestLogger();
    $other_spies = [];
    foreach (['audit_chain.stream', 'logger.channel.audit_chain'] as $id) {
      if ($id === $expected || !$this->container->has($id)) {
        continue;
      }
      $other_spies[$id] = new TestLogger();
      $this->container->set($id, $other_spies[$id]);
    }
    $this->installSiemSpy($expected_spy);

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle'      => 'article',
      'id'          => '1',
    ]);

    $this->assertCount(
      1,
      $expected_spy->records,
      'SIEM stream must emit on ' . $expected . '.',
    );
    foreach ($other_spies as $id => $spy) {
      $this->assertCount(
        0,
        $spy->records,
        'SIEM stream must not emit on ' . $id . '.',
      );
    }
  }

  /**
   * With stream_exclude_dblog set, the record moves to audit_chain.stream.
   *
   * Audit Chain 1.13.1 added the key. Older chains have no opt-in to test.
   */
  public function testExcludeDblogStreamsOnDedicatedSink(): void {
    if ($this->config('audit_chain.settings')->get('stream_exclude_dblog') === NULL) {
      $this->markTestSkipped('The installed Audit Chain has no stream_exclude_dblog setting.');
    }
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->set('stream_exclude_dblog', TRUE)
      ->save();
    $this->assertSame('audit_chain.stream', $this->siemChannelId());

    $channel_spy = new TestLogger();
    $this->container->set('logger.channel.audit_chain', $channel_spy);
    $stream_spy = new TestLogger();
    $this->installSiemSpy($stream_spy);

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle'      => 'article',
      'id'          => '1',
    ]);

    $this->assertCount(1, $stream_spy->records, 'SIEM stream must emit on audit_chain.stream.');
    $this->assertCount(0, $channel_spy->records, 'SIEM stream must not emit on logger.channel.audit_chain.');
  }

  /**
   * Asserts that no SIEM record is emitted when siem_enabled is FALSE.
   *
   * @covers ::log
   */
  public function testNoSiemEmitWhenDisabled(): void {
    $this->config('audit_chain.settings')
      ->set('stream_enabled', FALSE)
      ->save();

    $spy = new TestLogger();
    $this->installSiemSpy($spy);

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle'      => 'article',
      'id'          => '1',
    ]);

    $this->assertCount(0, $spy->records, 'No SIEM record should be emitted when siem_enabled is FALSE.');
  }

  /**
   * Asserts that exactly one structured record is emitted when siem_enabled.
   *
   * Verifies:
   * - Exactly one info-level record.
   * - Message is the stable sentinel string 'audit_chain_event'.
   * - Context contains operation, uid, entity_type, bundle, entity_id,
   *   timestamp, and row_hash.
   * - row_hash is a non-empty string (populated by the hash chain).
   *
   * @covers ::log
   */
  public function testSiemEmitOnAuditWrite(): void {
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->save();

    $spy = new TestLogger();
    $this->installSiemSpy($spy);
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle'      => 'article',
      'id'          => '42',
    ]);

    $this->assertCount(1, $spy->records, 'Exactly one SIEM record should be emitted per audit write.');

    $record = $spy->records[0];

    // Level must be info.
    $this->assertSame('info', $record['level'], 'SIEM record must be logged at info level.');

    // Message must be the stable sentinel string (no per-row interpolation).
    // It is audit_chain's now: the stream belongs to the chain, not to the MCP
    // policy in front of it.
    $this->assertSame('audit_chain_event', $record['message'], 'SIEM message must be the stable sentinel string.');

    $ctx = $record['context'];

    // Structured context must include all expected keys. 'channel' is the one
    // the extraction added; every other key predates it and must not have been
    // dropped in the move.
    foreach (['channel', 'operation', 'uid', 'entity_type', 'bundle', 'entity_id', 'timestamp', 'row_hash'] as $key) {
      $this->assertArrayHasKey($key, $ctx, "SIEM context must contain '{$key}'.");
    }

    $this->assertSame('mcp_sentinel', $ctx['channel'], "Context 'channel' must identify the consumer.");
    $this->assertSame('entity_save', $ctx['operation'], "Context 'operation' must match.");
    $this->assertSame('node', $ctx['entity_type'], "Context 'entity_type' must match.");
    $this->assertSame('article', $ctx['bundle'], "Context 'bundle' must match.");
    $this->assertSame('42', $ctx['entity_id'], "Context 'entity_id' must match.");
    $this->assertNotEmpty($ctx['row_hash'], 'SIEM context must contain a non-empty row_hash.');
  }

  /**
   * Asserts that a second audit entry emits a second SIEM record.
   *
   * Also verifies that the row_hash in each SIEM record matches the stored
   * row_hash in the audit log, so SIEM consumers can correlate records.
   *
   * @covers ::log
   */
  public function testSiemRecordRowHashMatchesAuditLog(): void {
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->save();

    $spy = new TestLogger();
    $this->installSiemSpy($spy);
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '10']);
    $logger->log('entity_delete', ['entity_type' => 'node', 'id' => '11']);

    $this->assertCount(2, $spy->records, 'Two audit writes must produce two SIEM records.');

    $rows = $db->select('audit_chain_log', 'l')
      ->fields('l', ['row_hash'])
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchCol();

    // Each SIEM record's row_hash must match the stored value for that entry.
    $this->assertSame(
      $rows[0],
      $spy->records[0]['context']['row_hash'],
      'First SIEM row_hash must match the first audit-log row_hash.',
    );
    $this->assertSame(
      $rows[1],
      $spy->records[1]['context']['row_hash'],
      'Second SIEM row_hash must match the second audit-log row_hash.',
    );
  }

  /**
   * Asserts that SIEM is not emitted when audit_enabled is FALSE.
   *
   * When the audit logger short-circuits (audit disabled), no DB row is
   * written and no SIEM record should be emitted.
   *
   * @covers ::log
   */
  public function testNoSiemEmitWhenAuditDisabled(): void {
    // Streaming is on at the chain, auditing is off at the MCP policy in front
    // of it — the point being that the policy short-circuits before the chain
    // is ever reached, so nothing is streamed.
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->save();
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', FALSE)
      ->save();

    $spy = new TestLogger();
    $this->installSiemSpy($spy);

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '1']);

    $this->assertCount(0, $spy->records, 'No SIEM record should be emitted when audit is disabled.');
  }

  /**
   * Channel id audit_chain actually streams SIEM records onto.
   */
  private function siemChannelId(): string {
    // 1.12.x has no dedicated stream service.
    if (!$this->container->has('audit_chain.stream')) {
      return 'logger.channel.audit_chain';
    }
    // 1.13.0 has no stream_exclude_dblog key and always streams on
    // audit_chain.stream. 1.13.1 and later stream there only when the key
    // is set.
    $exclude_dblog = $this->config('audit_chain.settings')->get('stream_exclude_dblog');
    return $exclude_dblog === NULL || $exclude_dblog
      ? 'audit_chain.stream'
      : 'logger.channel.audit_chain';
  }

  /**
   * Install the spy and rebuild the loggers that close over the channel.
   *
   * The audit_chain.logger service holds the stream channel from
   * construction. mcp_sentinel.audit_logger wraps that instance.
   * Resetting only the outer service would leave the inner one wired
   * to the real channel.
   */
  private function installSiemSpy(TestLogger $spy): void {
    $this->container->set($this->siemChannelId(), $spy);
    $this->container->set('audit_chain.logger', NULL);
    $this->container->set('mcp_sentinel.audit_logger', NULL);
  }

}
