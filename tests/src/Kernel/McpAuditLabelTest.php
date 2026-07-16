<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel test for non-string entity labels in the audit logger.
 *
 * For config entities (and some content entities) $entity->label() returns a
 * Drupal\Core\StringTranslation\TranslatableMarkup object rather than a plain
 * string. The audit logger receives that object as $metadata['label'] and used
 * to pass it straight to substr(), which throws a TypeError under PHP 8.x —
 * turning a legitimate governed save/delete into a fatal error inside
 * hook_entity_presave()/hook_entity_delete().
 *
 * This test exercises the log() write path with a TranslatableMarkup label and
 * asserts the row is written with the label stored as the rendered string.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAuditLabelTest extends KernelTestBase {

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
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * A TranslatableMarkup label is stored as its rendered string (no TypeError).
   *
   * @covers ::log
   */
  public function testLogStoresTranslatableMarkupLabelAsString(): void {
    $label = new TranslatableMarkup('Some @x label', ['@x' => 'config']);

    // Before the fix this call fatals with a TypeError because substr() cannot
    // accept the TranslatableMarkup object as its first argument.
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node_type',
      'bundle' => 'node_type',
      'id' => 'article',
      'label' => $label,
    ]);

    $row = $this->container->get('database')
      ->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $this->assertNotFalse($row, 'A row must be written when the label is a TranslatableMarkup.');
    $this->assertSame('entity_save', $row['operation']);
    // The label must be stored as the rendered translatable string.
    $this->assertSame('Some config label', $row['entity_label']);
  }

}
