<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Session\AccountProxyInterface;

/**
 * Manages content locks that block MCP writes to human-edited content.
 *
 * A lock pins an (entity_type, entity_id) pair in the
 * mcp_sentinel_content_locks table so a human editor can fence off content
 * that a governed agent must not overwrite. The presave guard consults
 * isLocked() and rejects governed writes to locked entities, giving humans a
 * deterministic "hands off" marker that survives across requests.
 *
 * Locks are time-bounded: expires_at stores an absolute Unix timestamp, with
 * the sentinel value 0 meaning "never expires" (a permanent, manually-managed
 * lock). Expiry is enforced on read (isLocked() excludes lapsed rows) and the
 * lapsed rows are reaped by hook_cron via releaseExpired(); permanent locks
 * (expires_at = 0) are deliberately never auto-reaped.
 */
class McpContentLock {

  /**
   * Default lock lifetime in seconds (one hour) when no TTL is supplied.
   */
  private const DEFAULT_TTL = 3600;

  /**
   * Constructs an McpContentLock service.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy (recorded as the lock owner in locked_by).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service (provides the request time used for lock timestamps).
   */
  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Locks an entity against governed MCP writes.
   *
   * Uses a MERGE upsert keyed on (entity_type, entity_id) so re-locking an
   * already-locked entity refreshes the owner, timestamp, expiry, and reason
   * rather than failing on a duplicate key.
   *
   * @param string $entityType
   *   The entity type ID to lock.
   * @param string $entityId
   *   The entity ID to lock.
   * @param string $reason
   *   Optional human-readable reason, truncated to the column width (512).
   * @param int|null $ttl
   *   Lock lifetime in seconds; the lock expires at now + $ttl. Pass 0 or NULL
   *   for a permanent lock (stored as expires_at = 0) that never auto-expires.
   */
  public function lock(string $entityType, string $entityId, string $reason = '', ?int $ttl = self::DEFAULT_TTL): void {
    $now = $this->time->getRequestTime();
    $this->database->merge('mcp_sentinel_content_locks')
      ->keys(['entity_type' => $entityType, 'entity_id' => $entityId])
      ->fields([
        'locked_by'  => $this->currentUser->id(),
        'locked_at'  => $now,
        // 0 is the "never expires" sentinel; a TTL becomes an absolute expiry.
        'expires_at' => $ttl ? ($now + $ttl) : 0,
        'reason'     => substr($reason, 0, 512),
      ])
      ->execute();
  }

  /**
   * Releases the lock on an entity, if any.
   *
   * @param string $entityType
   *   The entity type ID to unlock.
   * @param string $entityId
   *   The entity ID to unlock.
   */
  public function release(string $entityType, string $entityId): void {
    $this->database->delete('mcp_sentinel_content_locks')
      ->condition('entity_type', $entityType)
      ->condition('entity_id', $entityId)
      ->execute();
  }

  /**
   * Checks whether an entity is currently locked against governed MCP writes.
   *
   * Expired locks are excluded by a query condition rather than deleted, so
   * this read path never writes (avoiding lock contention and side effects on
   * a hot guard call). Lapsed rows are instead reaped by hook_cron via
   * releaseExpired(). A row counts as active when it never expires
   * (expires_at = 0) or its expiry is still in the future.
   *
   * @param string $entityType
   *   The entity type ID to check.
   * @param string $entityId
   *   The entity ID to check.
   *
   * @return bool
   *   TRUE if an active (non-expired) lock exists for the entity.
   */
  public function isLocked(string $entityType, string $entityId): bool {
    $now = $this->time->getRequestTime();
    return (bool) $this->database->select('mcp_sentinel_content_locks', 'l')
      ->condition('l.entity_type', $entityType)
      ->condition('l.entity_id', $entityId)
      ->where('l.expires_at = 0 OR l.expires_at > :now', [':now' => $now])
      ->countQuery()->execute()->fetchField();
  }

  /**
   * Returns the raw lock row for an entity, or NULL when no lock row exists.
   *
   * This returns the row regardless of expiry (it does not filter lapsed
   * locks), so callers that need an active-only answer should use isLocked().
   *
   * @param string $entityType
   *   The entity type ID to look up.
   * @param string $entityId
   *   The entity ID to look up.
   *
   * @return array|null
   *   The lock row (entity_type, entity_id, locked_by, locked_at, expires_at,
   *   reason), or NULL if the entity has no lock row.
   */
  public function getLockInfo(string $entityType, string $entityId): ?array {
    $row = $this->database->select('mcp_sentinel_content_locks', 'l')
      ->fields('l')
      ->condition('l.entity_type', $entityType)
      ->condition('l.entity_id', $entityId)
      ->execute()->fetchAssoc();
    return $row ?: NULL;
  }

  /**
   * Whether an active lock held by a DIFFERENT principal blocks the actor.
   *
   * The owner-aware conflict check every governed write channel shares
   * (d.o #3616541): the acting principal's own lock never blocks its write,
   * and ownership is resolved from the server-side current user — never from
   * anything a caller sends.
   *
   * @param string $entityType
   *   The entity type ID to check.
   * @param string $entityId
   *   The entity ID to check.
   *
   * @return bool
   *   TRUE when an active lock exists and is held by another principal.
   */
  public function conflictsForActor(string $entityType, string $entityId): bool {
    $row = $this->activeLockRow($entityType, $entityId);
    return $row !== NULL && (int) $row['locked_by'] !== (int) $this->currentUser->id();
  }

  /**
   * Whether the acting principal itself holds the active lock.
   *
   * @param string $entityType
   *   The entity type ID to check.
   * @param string $entityId
   *   The entity ID to check.
   *
   * @return bool
   *   TRUE when an active lock exists and the current user holds it.
   */
  public function heldByActor(string $entityType, string $entityId): bool {
    $row = $this->activeLockRow($entityType, $entityId);
    return $row !== NULL && (int) $row['locked_by'] === (int) $this->currentUser->id();
  }

  /**
   * Returns the active (non-expired) lock row, or NULL.
   *
   * @param string $entityType
   *   The entity type ID to look up.
   * @param string $entityId
   *   The entity ID to look up.
   *
   * @return array|null
   *   The active lock row, or NULL when none is active.
   */
  private function activeLockRow(string $entityType, string $entityId): ?array {
    $now = $this->time->getRequestTime();
    $row = $this->database->select('mcp_sentinel_content_locks', 'l')
      ->fields('l')
      ->condition('l.entity_type', $entityType)
      ->condition('l.entity_id', $entityId)
      ->where('l.expires_at = 0 OR l.expires_at > :now', [':now' => $now])
      ->execute()->fetchAssoc();
    return $row ?: NULL;
  }

  /**
   * Reaps all expired (time-bounded) locks. Called by hook_cron.
   *
   * Only rows with a positive expires_at that lies in the past are deleted.
   * Permanent locks (expires_at = 0) are excluded by the expires_at > 0
   * condition so a never-expiring lock is never silently cleared by cron.
   *
   * @return int
   *   The number of expired lock rows deleted.
   */
  public function releaseExpired(): int {
    $now = $this->time->getRequestTime();
    return (int) $this->database->delete('mcp_sentinel_content_locks')
      ->condition('expires_at', 0, '>')
      ->condition('expires_at', $now, '<')
      ->execute();
  }

}
