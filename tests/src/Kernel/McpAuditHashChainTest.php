<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Database\Statement\FetchAs;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the tamper-evident audit log hash chain.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAuditHashChainTest extends KernelTestBase {

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
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Asserts that three sequential log entries form a valid hash chain.
   *
   * @covers ::log
   * @covers ::verifyChain
   */
  public function testHashChainLinking(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '1',
      'label' => 'First',
    ]);
    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '2',
      'label' => 'Second',
    ]);
    $logger->log('entity_delete', [
      'entity_type' => 'node',
      'bundle' => 'page',
      'id' => '3',
      'label' => 'Third',
    ]);

    $rows = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll(FetchAs::Associative);

    $this->assertCount(3, $rows);

    // Row 1: prev_hash must be NULL (first row).
    $this->assertNull($rows[0]['prev_hash'], 'First row prev_hash must be NULL.');
    $this->assertNotEmpty($rows[0]['row_hash'], 'First row must have a row_hash.');

    // Row 2: prev_hash must equal row 1's row_hash.
    $this->assertSame(
      $rows[0]['row_hash'],
      $rows[1]['prev_hash'],
      'Row 2 prev_hash must equal row 1 row_hash.'
    );
    $this->assertNotEmpty($rows[1]['row_hash']);

    // Row 3: prev_hash must equal row 2's row_hash.
    $this->assertSame(
      $rows[1]['row_hash'],
      $rows[2]['prev_hash'],
      'Row 3 prev_hash must equal row 2 row_hash.'
    );
    $this->assertNotEmpty($rows[2]['row_hash']);

    // All three hashes must be distinct.
    $hashes = array_column($rows, 'row_hash');
    $this->assertSame(array_unique($hashes), $hashes, 'All row_hashes must be unique.');
  }

  /**
   * Asserts that row_hash values can be recomputed from the canonical content.
   *
   * @covers ::log
   * @covers ::verifyChain
   */
  public function testHashRecomputation(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '10',
      'label' => 'Alpha',
      'extra' => 'value',
    ]);
    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '11',
      'label' => 'Beta',
    ]);

    $rows = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll(FetchAs::Associative);

    // Recompute row 1 hash using the same canonical formula the service uses.
    $row = $rows[0];
    $metadata = json_decode((string) ($row['metadata'] ?? ''), TRUE) ?? [];
    ksort($metadata);
    $payload = [
      'bundle'      => $row['bundle'],
      'entity_id'   => (string) ($row['entity_id'] ?? ''),
      'entity_type' => $row['entity_type'],
      'metadata'    => $metadata,
      'operation'   => $row['operation'],
      'timestamp'   => (int) $row['timestamp'],
      'uid'         => (int) $row['uid'],
    ];
    $canonical = (string) json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $expected = hash('sha256', '|' . $canonical);
    $this->assertSame($expected, $row['row_hash'], 'Recomputed row 1 hash must match stored row_hash.');

    // Recompute row 2 using row 1's row_hash as prev_hash.
    $row2 = $rows[1];
    $metadata2 = json_decode((string) ($row2['metadata'] ?? ''), TRUE) ?? [];
    ksort($metadata2);
    $payload2 = [
      'bundle'      => $row2['bundle'],
      'entity_id'   => (string) ($row2['entity_id'] ?? ''),
      'entity_type' => $row2['entity_type'],
      'metadata'    => $metadata2,
      'operation'   => $row2['operation'],
      'timestamp'   => (int) $row2['timestamp'],
      'uid'         => (int) $row2['uid'],
    ];
    $canonical2 = (string) json_encode($payload2, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $expected2 = hash('sha256', $rows[0]['row_hash'] . '|' . $canonical2);
    $this->assertSame($expected2, $row2['row_hash'], 'Recomputed row 2 hash must match stored row_hash.');
  }

  /**
   * Asserts that verifyChain() returns ok=TRUE for an untampered log.
   *
   * @covers ::verifyChain
   */
  public function testVerifyChainOkOnCleanLog(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');

    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '2']);
    $logger->log('entity_delete', ['entity_type' => 'node', 'id' => '3']);

    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE for an untampered log.');
    $this->assertNull($result['broken_at']);
  }

  /**
   * Asserts that verifyChain() detects a tampered row.
   *
   * Tampering a row's metadata makes the stored row_hash no longer match the
   * recomputed hash, so verifyChain() must report ok=FALSE and the correct id.
   *
   * @covers ::verifyChain
   */
  public function testVerifyChainDetectsTampering(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1', 'label' => 'Original']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '2', 'label' => 'Untouched']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '3', 'label' => 'AlsoUntouched']);

    $rows = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchCol();

    // Tamper the metadata of the second row.
    $tampered_id = (int) $rows[1];
    $db->update('mcp_sentinel_audit_log')
      ->fields(['metadata' => json_encode(['tampered' => TRUE])])
      ->condition('id', $tampered_id)
      ->execute();

    $result = $logger->verifyChain();
    $this->assertFalse($result['ok'], 'verifyChain() must return ok=FALSE when a row is tampered.');
    $this->assertSame($tampered_id, $result['broken_at'], 'broken_at must be the id of the tampered row.');
  }

  /**
   * Asserts that verifyChain() returns ok=TRUE on an empty log.
   *
   * @covers ::verifyChain
   */
  public function testVerifyChainOkOnEmptyLog(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE on an empty log.');
    $this->assertNull($result['broken_at']);
  }

}
