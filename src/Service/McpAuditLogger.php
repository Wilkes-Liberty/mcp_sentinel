<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Session\AccountProxyInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Logs MCP operations to the mcp_sentinel_audit_log table.
 *
 * Governed requests are identified by the McpPolicyResolver (the validated
 * OAuth agent channel). Each entry is attributed to the authenticated account —
 * the acting admin (the OAuth subject) on the agent channel.
 *
 * Each row participates in a tamper-evident SHA-256 hash chain: row_hash is
 * computed over the previous row's hash plus a stable canonical serialization
 * of this row's content. Any modification of a historical row breaks the chain,
 * detectable by verifyChain().
 */
class McpAuditLogger {

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
   */
  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly RequestStack $requestStack,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
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
    $extra_metadata = array_diff_key($metadata, array_flip(['entity_type', 'bundle', 'id', 'label']));

    // Build the canonical JSON for this row (stable key order, no floats).
    $canonical = $this->buildCanonical(
      $timestamp,
      $uid,
      $op,
      $entity_type,
      $bundle,
      $entity_id,
      $extra_metadata,
    );

    // Fetch the most recent row_hash to use as prev_hash.
    $prev_hash = $this->getLatestRowHash();

    // Compute this row's hash: sha256(prev_hash | canonical).
    $row_hash = hash('sha256', ($prev_hash ?? '') . '|' . $canonical);

    $this->database->insert('mcp_sentinel_audit_log')
      ->fields([
        'timestamp'    => $timestamp,
        'uid'          => $uid,
        'operation'    => $op,
        'entity_type'  => $entity_type,
        'bundle'       => $bundle,
        'entity_id'    => $entity_id,
        'entity_label' => isset($metadata['label'])
          ? substr($metadata['label'], 0, 255)
          : NULL,
        'ip_address'   => $request?->getClientIp(),
        'user_agent'   => $request
          ? substr($request->headers->get('User-Agent', ''), 0, 512)
          : NULL,
        'metadata'     => json_encode($extra_metadata),
        'prev_hash'    => $prev_hash,
        'row_hash'     => $row_hash,
      ])
      ->execute();
  }

  /**
   * Walks all rows in id order and verifies the hash chain is intact.
   *
   * Each row's row_hash must equal sha256(prev_hash|canonical) and each row's
   * prev_hash must equal the immediately preceding row's row_hash. The first
   * row's prev_hash must be empty string (null stored as empty).
   *
   * @return array{ok: bool, broken_at: int|null}
   *   'ok' TRUE if the chain is intact; FALSE if any row fails verification.
   *   'broken_at' is the row id of the first broken link, or NULL if ok.
   */
  public function verifyChain(): array {
    $result = $this->database->select('mcp_sentinel_audit_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute();

    $prev_row_hash = '';

    foreach ($result as $row) {
      $row = (array) $row;

      $canonical = $this->buildCanonical(
        (int) $row['timestamp'],
        (int) $row['uid'],
        (string) $row['operation'],
        $row['entity_type'],
        $row['bundle'],
        (string) ($row['entity_id'] ?? ''),
        $this->decodeMetadata((string) ($row['metadata'] ?? '')),
      );

      // The stored prev_hash for the very first row must be empty / NULL.
      $stored_prev = (string) ($row['prev_hash'] ?? '');
      $expected_row_hash = hash('sha256', $stored_prev . '|' . $canonical);

      // Chain continuity: this row's prev_hash must match the prior row_hash.
      if ($stored_prev !== $prev_row_hash) {
        return ['ok' => FALSE, 'broken_at' => (int) $row['id']];
      }

      // Content integrity: the stored row_hash must match our recomputation.
      if ((string) ($row['row_hash'] ?? '') !== $expected_row_hash) {
        return ['ok' => FALSE, 'broken_at' => (int) $row['id']];
      }

      $prev_row_hash = (string) ($row['row_hash'] ?? '');
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
   * @return string|null
   *   The hex SHA-256 hash string, or NULL if no rows exist.
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
   * Builds a stable canonical JSON string for hashing.
   *
   * The canonical form has a fixed key order so the hash is reproducible
   * regardless of insertion order. All values are cast to their storage types.
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
    array $metadata,
  ): string {
    // Sort metadata keys for stable ordering.
    ksort($metadata);

    $payload = [
      'bundle'      => $bundle,
      'entity_id'   => $entity_id,
      'entity_type' => $entity_type,
      'metadata'    => $metadata,
      'operation'   => $operation,
      'timestamp'   => $timestamp,
      'uid'         => $uid,
    ];

    return (string) json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  }

}
