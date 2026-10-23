<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use ColinODell\PsrTestLogger\TestLogger;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Log\LoggerInterface;

/**
 * Kernel tests for SIEM streaming via audit_chain.
 *
 * audit_chain 1.13.0 writes successful audit_chain_event rows to
 * audit_chain.stream (every tagged logger except dblog). 1.12 wrote
 * them to logger.channel.audit_chain. The spy covers both. Errors
 * still use logger.channel.audit_chain.
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
   * Live SIEM identity is the audit_chain stream (1.13) or channel (1.12).
   */
  public function testLiveSiemChannelIsAuditChain(): void {
    $this->assertTrue(
      $this->container->has('logger.channel.audit_chain'),
      'Operational audit_chain logs still use logger.channel.audit_chain.',
    );
    if ($this->container->has('audit_chain.stream')) {
      $this->assertInstanceOf(
        LoggerInterface::class,
        $this->container->get('audit_chain.stream'),
        'SIEM streaming uses audit_chain.stream on audit_chain 1.13+.',
      );
    }
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

    $spy = $this->spySiemStream();

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

    $spy = $this->spySiemStream();
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

    $spy = $this->spySiemStream();
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

    $spy = $this->spySiemStream();

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '1']);

    $this->assertCount(0, $spy->records, 'No SIEM record should be emitted when audit is disabled.');
  }

  /**
   * Swap the SIEM sink for a spy and rebuild the loggers that hold it.
   *
   * audit_chain 1.13.0 emits successful stream rows on
   * audit_chain.stream. 1.12 emitted them on
   * logger.channel.audit_chain. A config save can construct
   * audit_chain.logger early, so both loggers are reset after the
   * swap.
   *
   * @return \ColinODell\PsrTestLogger\TestLogger
   *   The spy that will receive stream records.
   */
  private function spySiemStream(): TestLogger {
    $spy = new TestLogger();
    if ($this->container->has('audit_chain.stream')) {
      $this->container->set('audit_chain.stream', $spy);
    }
    $this->container->set('logger.channel.audit_chain', $spy);
    $this->container->set('audit_chain.logger', NULL);
    $this->container->set('mcp_sentinel.audit_logger', NULL);
    return $spy;
  }

}
