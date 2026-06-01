<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpAuditLoggerTest extends KernelTestBase {

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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_audit_log', 'mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * @covers ::log
   */
  public function testLogWritesRow(): void {
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '42',
      'label' => 'Test',
      'operation' => 'create',
    ]);

    $row = $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $this->assertSame('entity_save', $row['operation']);
    $this->assertSame('node', $row['entity_type']);
    $this->assertSame('42', $row['entity_id']);
    $this->assertStringContainsString('create', $row['metadata']);
  }

  /**
   * @covers ::log
   */
  public function testLogRespectsAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '1']);

    $count = (int) $this->container->get('database')
      ->select('mcp_sentinel_audit_log')->countQuery()->execute()->fetchField();
    $this->assertSame(0, $count);
  }

  /**
   * @covers ::pruneOldEntries
   */
  public function testPruneOldEntries(): void {
    $database = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();
    $database->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now - (100 * 86400),
      'uid' => 0,
      'operation' => 'old',
    ])->execute();
    $database->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now,
      'uid' => 0,
      'operation' => 'fresh',
    ])->execute();

    // Retention defaults to 90 days; the 100-day-old row should be pruned.
    $pruned = $this->container->get('mcp_sentinel.audit_logger')->pruneOldEntries();
    $this->assertSame(1, $pruned);
    $remaining = (int) $database->select('mcp_sentinel_audit_log')->countQuery()->execute()->fetchField();
    $this->assertSame(1, $remaining);
  }

}
