<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Database\Statement\FetchAs;
use Drupal\encrypt\Entity\EncryptionProfile;
use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for at-rest encryption of audit metadata.
 *
 * Uses the encrypt_test module's TestEncryptionMethod (str_rot13 + key prefix
 * — deterministic and reversible, no libsodium dependency) to verify:
 *   (a) When a profile is configured, the raw DB metadata column is NOT the
 *       plain-text JSON.
 *   (b) decodeMetadata() round-trips back to the original array.
 *   (c) verifyChain() still passes (hash chain hashes plaintext, not cipher).
 *   (d) Without a profile, rows remain in plain JSON (backward compat).
 *   (e) decodeMetadata() falls back to plain JSON decode for pre-encryption
 *       rows when a profile is now configured (graceful legacy row handling).
 *
 * The encrypt_test module ships with drupal/encrypt and exposes a
 * test_encryption_method plugin that requires a 16-byte encryption key.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAuditEncryptionTest extends KernelTestBase {

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
    'encrypt_test',
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
   * Creates a test encryption key and profile, returning the profile ID.
   *
   * Uses the encrypt_test module's 'test_encryption_method' plugin which
   * requires a 16-character (128-bit) encryption key.
   *
   * @return string
   *   The encryption profile entity ID.
   */
  private function createTestEncryptionProfile(): string {
    Key::create([
      'id' => 'mcp_test_enc_key',
      'label' => 'MCP test encryption key',
      'key_type' => 'encryption',
      'key_type_settings' => ['key_size' => '128'],
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'sixteenbytekey!!'],
    ])->save();

    EncryptionProfile::create([
      'id' => 'mcp_test_enc_profile',
      'label' => 'MCP test encryption profile',
      'encryption_method' => 'test_encryption_method',
      'encryption_key' => 'mcp_test_enc_key',
    ])->save();

    return 'mcp_test_enc_profile';
  }

  /**
   * When a profile is configured, the DB metadata column is ciphertext.
   *
   * @covers ::log
   * @covers ::encodeMetadata
   */
  public function testMetadataStoredAsCiphertext(): void {
    $profile_id = $this->createTestEncryptionProfile();
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', $profile_id)
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '99',
      'label' => 'Encrypted row',
      'secret_note' => 'do not store plaintext',
    ]);

    $row = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['metadata'])
      ->execute()
      ->fetchAssoc();

    $this->assertNotEmpty($row['metadata'], 'metadata column must not be empty.');

    // The stored value must NOT be the original plaintext JSON.
    $this->assertStringNotContainsString(
      'secret_note',
      (string) $row['metadata'],
      'DB metadata column must not contain plaintext field names when encryption is enabled.',
    );
    $this->assertStringNotContainsString(
      'do not store plaintext',
      (string) $row['metadata'],
      'DB metadata column must not contain plaintext values when encryption is enabled.',
    );
  }

  /**
   * DecodeMetadata() round-trips through encrypt/decrypt to the original array.
   *
   * @covers ::log
   * @covers ::decodeMetadata
   */
  public function testDecodeMetadataRoundTrips(): void {
    $profile_id = $this->createTestEncryptionProfile();
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', $profile_id)
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '100',
      'label' => 'Round-trip test',
      'custom_key' => 'custom_value',
      'nested' => ['foo' => 'bar'],
    ]);

    $row = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['metadata'])
      ->execute()
      ->fetchAssoc();

    $decoded = $logger->decodeMetadata((string) $row['metadata']);

    // The decoded array must contain the extra metadata (entity_type, bundle,
    // id, label are stored in dedicated columns, not metadata).
    $this->assertArrayHasKey('custom_key', $decoded, 'Round-tripped metadata must contain custom_key.');
    $this->assertSame('custom_value', $decoded['custom_key'], 'custom_key value must survive encrypt/decrypt.');
    $this->assertArrayHasKey('nested', $decoded, 'Nested arrays must survive encrypt/decrypt.');
    $this->assertSame(['foo' => 'bar'], $decoded['nested']);
  }

  /**
   * VerifyChain() passes even when encryption is enabled.
   *
   * The hash chain is computed over the plaintext canonical content BEFORE
   * encryption, so verifyChain() must decrypt via decodeMetadata() and still
   * produce the correct hash.
   *
   * @covers ::log
   * @covers ::verifyChain
   */
  public function testVerifyChainPassesWithEncryption(): void {
    $profile_id = $this->createTestEncryptionProfile();
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', $profile_id)
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '1',
      'label' => 'Chain row 1',
    ]);
    $logger->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '2',
      'label' => 'Chain row 2',
    ]);
    $logger->log('entity_delete', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '3',
      'label' => 'Chain row 3',
    ]);

    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE when encryption is enabled.');
    $this->assertNull($result['broken_at']);
  }

  /**
   * Without a profile, metadata is stored as plain JSON (backward compat).
   *
   * @covers ::log
   */
  public function testNoEncryptionWhenNoProfileConfigured(): void {
    // Ensure no profile is set (default).
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', '')
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', [
      'entity_type' => 'node',
      'id' => '50',
      'plaintext_key' => 'plaintext_value',
    ]);

    $row = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['metadata'])
      ->execute()
      ->fetchAssoc();

    $this->assertStringContainsString(
      'plaintext_key',
      (string) $row['metadata'],
      'Without an encryption profile, metadata must be stored as plain JSON.',
    );
  }

  /**
   * DecodeMetadata() falls back to plain JSON decode for legacy plaintext rows.
   *
   * Simulates the scenario where a site enables encryption after rows were
   * already written in plaintext: decodeMetadata() must still return the
   * correct array for those old rows.
   *
   * @covers ::decodeMetadata
   */
  public function testDecodeMetadataFallsBackForPlaintextLegacyRows(): void {
    $db = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();

    // Insert a plaintext row directly (simulating a pre-encryption audit row).
    $db->insert('mcp_sentinel_audit_log')->fields([
      'timestamp' => $now,
      'uid' => 0,
      'operation' => 'legacy_op',
      'metadata' => json_encode(['legacy_field' => 'legacy_value']),
    ])->execute();

    // Now enable encryption.
    $profile_id = $this->createTestEncryptionProfile();
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', $profile_id)
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');

    $row = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['metadata'])
      ->execute()
      ->fetchAssoc();

    // decodeMetadata() must fall back to plain JSON when decryption fails.
    $decoded = $logger->decodeMetadata((string) $row['metadata']);
    $this->assertArrayHasKey('legacy_field', $decoded, 'Legacy plaintext rows must still be decodable after encryption is enabled.');
    $this->assertSame('legacy_value', $decoded['legacy_field']);
  }

  /**
   * Chain integrity: verifyChain() detects tampering even with encryption on.
   *
   * @covers ::verifyChain
   */
  public function testVerifyChainDetectsTamperingWithEncryption(): void {
    $profile_id = $this->createTestEncryptionProfile();
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', $profile_id)
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '1', 'label' => 'First']);
    $logger->log('entity_save', ['entity_type' => 'node', 'id' => '2', 'label' => 'Second']);

    $ids = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchCol();

    // Tamper the row_hash of the first row to break the chain.
    $tampered_id = (int) $ids[0];
    $db->update('mcp_sentinel_audit_log')
      ->fields(['row_hash' => 'tampered_hash_value'])
      ->condition('id', $tampered_id)
      ->execute();

    $result = $logger->verifyChain();
    $this->assertFalse($result['ok'], 'verifyChain() must detect tampering when encryption is enabled.');
  }

  /**
   * Encrypted rows from multiple log() calls form a valid hash chain.
   *
   * @covers ::log
   * @covers ::verifyChain
   */
  public function testMultipleEncryptedRowsHaveValidChain(): void {
    $profile_id = $this->createTestEncryptionProfile();
    $this->config('mcp_sentinel.settings')
      ->set('audit_encryption_profile', $profile_id)
      ->save();

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $db = $this->container->get('database');

    for ($i = 1; $i <= 5; $i++) {
      $logger->log('entity_save', [
        'entity_type' => 'node',
        'bundle' => 'article',
        'id' => (string) $i,
        'label' => "Row {$i}",
        'index' => $i,
      ]);
    }

    $rows = $db->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['id', 'prev_hash', 'row_hash', 'metadata'])
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll(FetchAs::Associative);

    $this->assertCount(5, $rows);

    // Every metadata column must be non-empty ciphertext.
    foreach ($rows as $row) {
      $this->assertNotEmpty($row['metadata'], 'Each encrypted row must have a non-empty metadata column.');
      $this->assertStringNotContainsString('"index"', (string) $row['metadata'], 'Metadata must not contain plaintext JSON keys.');
    }

    // The hash chain must be intact.
    $result = $logger->verifyChain();
    $this->assertTrue($result['ok'], 'verifyChain() must return ok=TRUE for a 5-entry encrypted chain.');
    $this->assertNull($result['broken_at']);
  }

}
