<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Database\Statement\FetchAs;
use Drupal\key\Entity\Key;
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
   * The canonical payload now includes entity_label, ip_address, and
   * user_agent in fixed key order (FIX I2).
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

    // Helper: reproduce buildCanonical() as McpAuditLogger does (FIX I2).
    $buildCanonical = static function (array $row): string {
      $metadata = json_decode((string) ($row['metadata'] ?? ''), TRUE) ?? [];
      ksort($metadata);
      $payload = [
        'bundle'       => $row['bundle'],
        'entity_id'    => (string) ($row['entity_id'] ?? ''),
        'entity_label' => isset($row['entity_label'])
          ? (string) $row['entity_label']
          : NULL,
        'entity_type'  => $row['entity_type'],
        'ip_address'   => isset($row['ip_address'])
          ? (string) $row['ip_address']
          : NULL,
        'metadata'     => $metadata,
        'operation'    => substr((string) $row['operation'], 0, 64),
        'timestamp'    => (int) $row['timestamp'],
        'uid'          => (int) $row['uid'],
        'user_agent'   => isset($row['user_agent'])
          ? (string) $row['user_agent']
          : NULL,
      ];
      return (string) json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
      );
    };

    // Recompute row 1 hash (prev_hash is NULL → use empty string).
    $row = $rows[0];
    $canonical = $buildCanonical($row);
    $expected = hash('sha256', '|' . $canonical);
    $this->assertSame($expected, $row['row_hash'], 'Recomputed row 1 hash must match stored row_hash.');

    // Recompute row 2 using row 1's row_hash as prev_hash.
    $row2 = $rows[1];
    $canonical2 = $buildCanonical($row2);
    $expected2 = hash('sha256', $rows[0]['row_hash'] . '|' . $canonical2);
    $this->assertSame($expected2, $row2['row_hash'], 'Recomputed row 2 hash must match stored row_hash.');

    // verifyChain() must agree.
    $this->assertTrue($logger->verifyChain()['ok']);
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

  /**
   * FIX C1: verifyChain() must skip pre-update_10003 rows (NULL row_hash).
   *
   * Rows written before update_10003 have NULL prev_hash and NULL row_hash.
   * verifyChain() must skip them and treat the first chained row after the gap
   * as the start of a fresh chain segment (its prev_hash is also NULL/empty).
   *
   * @covers ::verifyChain
   */
  public function testVerifyChainSkipsPreUpdateNullHashRows(): void {
    $db = $this->container->get('database');
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Insert two pre-update_10003 rows directly (NULL prev_hash + row_hash).
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now - 200,
      'uid'       => 0,
      'operation' => 'legacy_op',
      'prev_hash' => NULL,
      'row_hash'  => NULL,
    ])->execute();
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now - 100,
      'uid'       => 0,
      'operation' => 'legacy_op2',
      'prev_hash' => NULL,
      'row_hash'  => NULL,
    ])->execute();

    // Now log two chained rows via the logger (these will have proper hashes).
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '2']);

    // verifyChain() must return ok=TRUE: it skips the NULL rows and verifies
    // only the two chained rows that follow them.
    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE when pre-update NULL rows precede valid chained rows.');
    $this->assertNull($result['broken_at']);
  }

  /**
   * FIX C1: verifyChain() with only pre-update NULL-hash rows returns ok=TRUE.
   *
   * @covers ::verifyChain
   */
  public function testVerifyChainAllNullHashRowsOk(): void {
    $db = $this->container->get('database');
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Only legacy rows, no chained rows at all.
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now - 200,
      'uid'       => 0,
      'operation' => 'legacy_only',
      'prev_hash' => NULL,
      'row_hash'  => NULL,
    ])->execute();

    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE when all rows are pre-update NULL-hash rows.');
    $this->assertNull($result['broken_at']);
  }

  /**
   * FIX C2: HMAC-SHA256 is used when audit_hash_key is configured.
   *
   * Configures a Key entity with a known secret, logs two entries, then
   * verifies:
   * 1. verifyChain() passes (the service reads the same key for verify).
   * 2. The stored row_hash equals hash_hmac('sha256', prev.'|'.canonical, key).
   *
   * @covers ::log
   * @covers ::verifyChain
   */
  public function testHmacKeyedHashChain(): void {
    $key_value = 'audit-test-secret-key-xK9m';

    Key::create([
      'id' => 'mcp_test_audit_key',
      'label' => 'MCP test audit key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => $key_value],
    ])->save();

    $this->config('mcp_sentinel.settings')
      ->set('audit_hash_key', 'mcp_test_audit_key')
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle'      => 'article',
      'id'          => '20',
      'label'       => 'HMAC row 1',
    ]);
    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle'      => 'article',
      'id'          => '21',
      'label'       => 'HMAC row 2',
    ]);

    $rows = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll(FetchAs::Associative);

    $this->assertCount(2, $rows);

    // Helper: reproduce buildCanonical() as McpAuditLogger does.
    $buildCanonical = static function (array $row): string {
      $metadata = json_decode((string) ($row['metadata'] ?? ''), TRUE) ?? [];
      ksort($metadata);
      $payload = [
        'bundle'       => $row['bundle'],
        'entity_id'    => (string) ($row['entity_id'] ?? ''),
        'entity_label' => isset($row['entity_label'])
          ? (string) $row['entity_label']
          : NULL,
        'entity_type'  => $row['entity_type'],
        'ip_address'   => isset($row['ip_address'])
          ? (string) $row['ip_address']
          : NULL,
        'metadata'     => $metadata,
        'operation'    => substr((string) $row['operation'], 0, 64),
        'timestamp'    => (int) $row['timestamp'],
        'uid'          => (int) $row['uid'],
        'user_agent'   => isset($row['user_agent'])
          ? (string) $row['user_agent']
          : NULL,
      ];
      return (string) json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
      );
    };

    // Row 1: first row has no prev_hash, so the hash input starts with '|'.
    $canonical1 = $buildCanonical($rows[0]);
    $expected1 = hash_hmac('sha256', '|' . $canonical1, $key_value);
    $this->assertSame(
      $expected1,
      $rows[0]['row_hash'],
      'Row 1 must use HMAC-SHA256 with the configured key.',
    );

    // Row 2: prev_hash is row 1's row_hash.
    $canonical2 = $buildCanonical($rows[1]);
    $expected2 = hash_hmac('sha256', $rows[0]['row_hash'] . '|' . $canonical2, $key_value);
    $this->assertSame(
      $expected2,
      $rows[1]['row_hash'],
      'Row 2 must use HMAC-SHA256 with the configured key.',
    );

    // HMAC hash must differ from plain SHA-256.
    $plain1 = hash('sha256', '|' . $canonical1);
    $this->assertNotSame(
      $plain1,
      $rows[0]['row_hash'],
      'HMAC row_hash must differ from plain SHA-256.',
    );

    // verifyChain() must pass (it re-resolves the same key).
    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE for an HMAC-keyed untampered chain.');
    $this->assertNull($result['broken_at']);
  }

  /**
   * FIX C2: verifyChain() detects tampering even with an HMAC key configured.
   *
   * @covers ::verifyChain
   */
  public function testHmacKeyedChainDetectsTampering(): void {
    $key_value = 'tamper-detect-key-v2';

    Key::create([
      'id' => 'mcp_tamper_key',
      'label' => 'MCP tamper key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => $key_value],
    ])->save();

    $this->config('mcp_sentinel.settings')
      ->set('audit_hash_key', 'mcp_tamper_key')
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '30', 'label' => 'Intact']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '31', 'label' => 'ToTamper']);

    $ids = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchCol();

    $tampered_id = (int) $ids[1];
    $db->update('mcp_sentinel_audit_log')
      ->fields(['entity_label' => 'Tampered'])
      ->condition('id', $tampered_id)
      ->execute();

    $result = $logger->verifyChain();
    $this->assertFalse($result['ok'], 'verifyChain() must detect tampering in an HMAC-keyed chain.');
    $this->assertSame($tampered_id, $result['broken_at']);
  }

}
