<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\key\KeyRepositoryInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Logs MCP operations to the mcp_sentinel_audit_log table.
 *
 * Governed requests are identified by the McpPolicyResolver (the validated
 * OAuth agent channel). Each entry is attributed to the authenticated account —
 * the acting admin (the OAuth subject) on the agent channel.
 *
 * Each row participates in a tamper-evident hash chain: row_hash is computed
 * over the previous row's hash plus a stable canonical serialization of this
 * row's content using HMAC-SHA256 (when a Key is configured via
 * audit_hash_key) or plain SHA-256 as a fallback. Any modification of a
 * historical row breaks the chain, detectable by verifyChain().
 *
 * The canonical payload includes: bundle, entity_id, entity_label, entity_type,
 * ip_address, metadata, operation, timestamp, uid, user_agent (fixed order).
 */
class McpAuditLogger {

  /**
   * Lock name used to serialize the read-latest-then-insert critical section.
   */
  private const CHAIN_LOCK = 'mcp_sentinel_audit_chain';

  /**
   * Constructs an McpAuditLogger.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack (used for IP address and User-Agent in log entries).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\key\KeyRepositoryInterface $keyRepository
   *   The Key repository (resolves the audit HMAC signing key).
   * @param \Drupal\Core\Lock\LockBackendInterface $lock
   *   The lock backend (serializes the read-latest-then-insert critical
   *   section to prevent hash-chain races under concurrent writes).
   */
  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly RequestStack $requestStack,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly KeyRepositoryInterface $keyRepository,
    private readonly LockBackendInterface $lock,
  ) {}

  /**
   * Logs an MCP operation.
   *
   * @param string $operation
   *   A short operation identifier (e.g. 'entity_save', 'entity_delete').
   * @param array $metadata
   *   Optional metadata. Recognised keys: entity_type, bundle, id, label.
   *   Remaining keys are JSON-encoded into the metadata column.
   */
  public function log(string $operation, array $metadata = []): void {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    if (!$config->get('audit_enabled')) {
      return;
    }
    if (str_starts_with($operation, 'entity_read') && !$config->get('audit_log_reads')) {
      return;
    }

    $request = $this->requestStack->getCurrentRequest();
    $timestamp = $this->time->getRequestTime();
    $uid = (int) $this->currentUser->id();
    $op = substr($operation, 0, 64);
    $entity_type = $metadata['entity_type'] ?? NULL;
    $bundle = $metadata['bundle'] ?? NULL;
    $entity_id = (string) ($metadata['id'] ?? '');
    $entity_label = isset($metadata['label'])
      ? substr($metadata['label'], 0, 255)
      : NULL;
    $ip_address = $request?->getClientIp();
    $user_agent = $request
      ? substr($request->headers->get('User-Agent', ''), 0, 512)
      : NULL;
    $extra_metadata = array_diff_key($metadata, array_flip(['entity_type', 'bundle', 'id', 'label']));

    $key_value = $this->resolveHashKey($config->get('audit_hash_key'));

    // Serialize the read-latest-then-insert critical section.
    // If the lock cannot be acquired we still write (never drop audit entries)
    // but the guarantee is best-effort for that request.
    $locked = $this->lock->acquire(self::CHAIN_LOCK, 3.0);
    try {
      // Build the canonical JSON for this row (stable key order, no floats).
      $canonical = $this->buildCanonical(
        $timestamp,
        $uid,
        $op,
        $entity_type,
        $bundle,
        $entity_id,
        $entity_label,
        $ip_address,
        $user_agent,
        $extra_metadata,
      );

      // Fetch the most recent row_hash to use as prev_hash.
      $prev_hash = $this->getLatestRowHash();

      // Compute this row's hash: hmac-sha256(prev_hash|canonical) or fallback.
      $row_hash = $this->hashRow($prev_hash ?? '', $canonical, $key_value);

      $this->database->insert('mcp_sentinel_audit_log')
        ->fields([
          'timestamp'    => $timestamp,
          'uid'          => $uid,
          'operation'    => $op,
          'entity_type'  => $entity_type,
          'bundle'       => $bundle,
          'entity_id'    => $entity_id,
          'entity_label' => $entity_label,
          'ip_address'   => $ip_address,
          'user_agent'   => $user_agent,
          'metadata'     => json_encode($extra_metadata),
          'prev_hash'    => $prev_hash,
          'row_hash'     => $row_hash,
        ])
        ->execute();
    }
    finally {
      if ($locked) {
        $this->lock->release(self::CHAIN_LOCK);
      }
    }
  }

  /**
   * Walks all rows in id order and verifies the hash chain is intact.
   *
   * Rows written before update_10003 (NULL/empty row_hash) are skipped; the
   * first chained row after a gap starts a fresh chain segment whose prev_hash
   * must itself be NULL/empty.
   *
   * Each chained row's row_hash must equal hashRow(prev_hash, canonical) and
   * each row's prev_hash must equal the immediately preceding chained row's
   * row_hash.
   *
   * @return array{ok: bool, broken_at: int|null}
   *   'ok' TRUE if the chain is intact; FALSE if any row fails verification.
   *   'broken_at' is the row id of the first broken link, or NULL if ok.
   */
  public function verifyChain(): array {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    $key_value = $this->resolveHashKey($config->get('audit_hash_key'));

    $result = $this->database->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute();

    $prev_row_hash = '';

    foreach ($result as $row) {
      $row = (array) $row;

      // FIX C1: skip pre-update_10003 rows whose row_hash was never populated.
      // Reset prev_row_hash so the first chained row after this gap can start
      // a fresh chain segment (its prev_hash will also be NULL/empty).
      if ($row['row_hash'] === NULL || $row['row_hash'] === '') {
        $prev_row_hash = '';
        continue;
      }

      // FIX M2: truncate operation to 64 chars before buildCanonical, matching
      // the write path, so a future column-width change cannot desync hashes.
      $op = substr((string) $row['operation'], 0, 64);

      $canonical = $this->buildCanonical(
        (int) $row['timestamp'],
        (int) $row['uid'],
        $op,
        $row['entity_type'],
        $row['bundle'],
        (string) ($row['entity_id'] ?? ''),
        isset($row['entity_label']) ? (string) $row['entity_label'] : NULL,
        isset($row['ip_address']) ? (string) $row['ip_address'] : NULL,
        isset($row['user_agent']) ? (string) $row['user_agent'] : NULL,
        $this->decodeMetadata((string) ($row['metadata'] ?? '')),
      );

      // The stored prev_hash for the very first chained row must be empty /
      // NULL; subsequent rows must match the previous chained row's row_hash.
      $stored_prev = (string) ($row['prev_hash'] ?? '');
      $expected_row_hash = $this->hashRow($stored_prev, $canonical, $key_value);

      // Chain continuity: this row's prev_hash must match the prior row_hash.
      if ($stored_prev !== $prev_row_hash) {
        return ['ok' => FALSE, 'broken_at' => (int) $row['id']];
      }

      // Content integrity: the stored row_hash must match our recomputation.
      if ((string) $row['row_hash'] !== $expected_row_hash) {
        return ['ok' => FALSE, 'broken_at' => (int) $row['id']];
      }

      $prev_row_hash = (string) $row['row_hash'];
    }

    return ['ok' => TRUE, 'broken_at' => NULL];
  }

  /**
   * Decodes stored metadata JSON into an array.
   *
   * This is the single accessor for metadata reads. Future features (e.g.
   * at-rest encryption) only need to update this method.
   *
   * @param string $stored
   *   The raw stored metadata string from the database.
   *
   * @return array
   *   Decoded metadata, or an empty array on failure.
   */
  public function decodeMetadata(string $stored): array {
    if ($stored === '') {
      return [];
    }
    $decoded = json_decode($stored, TRUE);
    return is_array($decoded) ? $decoded : [];
  }

  /**
   * Deletes log entries older than the configured retention period.
   *
   * @return int
   *   Number of rows deleted.
   */
  public function pruneOldEntries(): int {
    $days = (int) $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('audit_retention_days');
    if ($days <= 0) {
      return 0;
    }
    $cutoff = $this->time->getRequestTime() - ($days * 86400);
    return (int) $this->database->delete('mcp_sentinel_audit_log')
      ->condition('timestamp', $cutoff, '<')
      ->execute();
  }

  /**
   * Returns the row_hash of the most-recently inserted row, or NULL.
   *
   * Must be called while holding CHAIN_LOCK to be race-free.
   *
   * @return string|null
   *   The hex hash string, or NULL if no rows exist.
   */
  private function getLatestRowHash(): ?string {
    $hash = $this->database->select('mcp_sentinel_audit_log', 'l')
      ->fields('l', ['row_hash'])
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchField();

    return ($hash !== FALSE && $hash !== NULL && $hash !== '') ? (string) $hash : NULL;
  }

  /**
   * Computes the row hash using HMAC-SHA256 (keyed) or SHA-256 (fallback).
   *
   * HMAC-SHA256 is used when a Key value has been resolved from the
   * audit_hash_key setting; otherwise plain SHA-256 is used so the chain still
   * works on sites that have not configured a signing key.
   *
   * @param string $prev_hash
   *   The previous row's hash (empty string for the first row).
   * @param string $canonical
   *   The stable canonical JSON for the current row.
   * @param string $key_value
   *   The resolved HMAC signing key, or empty string for the SHA-256 fallback.
   *
   * @return string
   *   Lowercase hex hash string (64 chars for SHA-256/HMAC-SHA256).
   */
  private function hashRow(string $prev_hash, string $canonical, string $key_value): string {
    $message = $prev_hash . '|' . $canonical;
    if ($key_value !== '') {
      return hash_hmac('sha256', $message, $key_value);
    }
    return hash('sha256', $message);
  }

  /**
   * Resolves the HMAC signing key value from the configured Key entity.
   *
   * Returns an empty string if no key is configured or the Key cannot be
   * found, so the caller falls back to plain SHA-256.
   *
   * @param mixed $key_id
   *   The audit_hash_key config value (Key entity ID string or NULL).
   *
   * @return string
   *   The key value, or empty string when unavailable.
   */
  private function resolveHashKey(mixed $key_id): string {
    $id = (string) ($key_id ?? '');
    if ($id === '') {
      return '';
    }
    $key = $this->keyRepository->getKey($id);
    if (!$key) {
      return '';
    }
    return (string) $key->getKeyValue();
  }

  /**
   * Builds a stable canonical JSON string for hashing.
   *
   * The canonical form has a fixed key order so the hash is reproducible
   * regardless of insertion order. All values are cast to their storage types.
   * Forensic columns entity_label, ip_address, and user_agent are included
   * so that post-hoc alteration of those fields also breaks the chain.
   *
   * Fixed payload key order:
   *   bundle, entity_id, entity_label, entity_type, ip_address, metadata,
   *   operation, timestamp, uid, user_agent.
   *
   * @param int $timestamp
   *   Unix timestamp.
   * @param int $uid
   *   User ID.
   * @param string $operation
   *   Operation name (already truncated to 64 chars).
   * @param string|null $entity_type
   *   Entity type, or NULL.
   * @param string|null $bundle
   *   Bundle, or NULL.
   * @param string $entity_id
   *   Entity ID string.
   * @param string|null $entity_label
   *   Entity label (already truncated to 255 chars), or NULL.
   * @param string|null $ip_address
   *   Client IP address, or NULL.
   * @param string|null $user_agent
   *   HTTP User-Agent (already truncated to 512 chars), or NULL.
   * @param array $metadata
   *   Extra metadata (already decoded from JSON).
   *
   * @return string
   *   JSON string with UTF-8-safe encoding and unescaped slashes/unicode.
   */
  private function buildCanonical(
    int $timestamp,
    int $uid,
    string $operation,
    ?string $entity_type,
    ?string $bundle,
    string $entity_id,
    ?string $entity_label,
    ?string $ip_address,
    ?string $user_agent,
    array $metadata,
  ): string {
    // Sort metadata keys for stable ordering.
    ksort($metadata);

    $payload = [
      'bundle'       => $bundle,
      'entity_id'    => $entity_id,
      'entity_label' => $entity_label,
      'entity_type'  => $entity_type,
      'ip_address'   => $ip_address,
      'metadata'     => $metadata,
      'operation'    => $operation,
      'timestamp'    => $timestamp,
      'uid'          => $uid,
      'user_agent'   => $user_agent,
    ];

    return (string) json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  }

}
