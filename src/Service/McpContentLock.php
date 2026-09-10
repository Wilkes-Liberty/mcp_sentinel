<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
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
 *
 * When contrib Content Lock is installed, owner-aware conflict / isLocked
 * checks also consult that module's service (d.o #3622400). A human opening
 * /node/N/edit writes the contrib table, not mcp_sentinel_content_locks;
 * without this consult a governed JSON:API PATCH would succeed while the
 * editor still has the form open. Content Lock remains optional: the
 * editorial service is injected with '@?content_lock' and is a no-op when
 * absent. The "break content lock" permission is not honoured on the
 * governed path — that permission is for humans in the UI.
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
   * @param object|null $editorialLock
   *   The contrib content_lock service, or NULL when that module is not
   *   installed (injected with the optional-service '@?content_lock' syntax).
   *   Duck-typed so phpstan does not require the optional package.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface|null $entityTypeManager
   *   Used to load the entity when a caller has only type+id and contrib
   *   Content Lock must be consulted. NULL is accepted so existing unit
   *   tests that construct this service with three arguments keep working;
   *   without it, the contrib consult is skipped unless the caller passes
   *   the entity.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly TimeInterface $time,
    private readonly mixed $editorialLock = NULL,
    private readonly ?EntityTypeManagerInterface $entityTypeManager = NULL,
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
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The entity, when the caller already has it.
   *
   * @return bool
   *   TRUE if an active (non-expired) Sentinel or contrib lock exists.
   */
  public function isLocked(string $entityType, string $entityId, ?EntityInterface $entity = NULL): bool {
    if ($this->sentinelIsLocked($entityType, $entityId)) {
      return TRUE;
    }
    return $this->fetchEditorialLock($entity ?? $this->loadEntity($entityType, $entityId)) !== FALSE;
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
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The entity, when the caller already has it. Avoids a load when falling
   *   through to contrib Content Lock.
   *
   * @return array|null
   *   The lock row (entity_type, entity_id, locked_by, locked_at, expires_at,
   *   reason), or NULL if the entity has no lock row. A contrib-only lock
   *   is returned with source = content_lock.
   */
  public function getLockInfo(string $entityType, string $entityId, ?EntityInterface $entity = NULL): ?array {
    $row = $this->database->select('mcp_sentinel_content_locks', 'l')
      ->fields('l')
      ->condition('l.entity_type', $entityType)
      ->condition('l.entity_id', $entityId)
      ->execute()->fetchAssoc();
    if ($row) {
      return $row;
    }
    $editorial = $this->fetchEditorialLock($entity ?? $this->loadEntity($entityType, $entityId));
    if ($editorial === FALSE) {
      return NULL;
    }
    return [
      'entity_type' => $entityType,
      'entity_id' => $entityId,
      'locked_by' => (int) $editorial->uid,
      'locked_at' => (int) ($editorial->timestamp ?? 0),
      'expires_at' => 0,
      'reason' => 'content_lock',
      'source' => 'content_lock',
    ];
  }

  /**
   * Whether an active lock held by a DIFFERENT principal blocks the actor.
   *
   * The owner-aware conflict check every governed write channel shares
   * (d.o #3616541 / #3622400): the acting principal's own lock never
   * blocks its write, and ownership is resolved from the server-side
   * current user — never from anything a caller sends. A contrib Content
   * Lock row held by a different uid is the same conflict as a Sentinel
   * row held by a different uid.
   *
   * @param string $entityType
   *   The entity type ID to check.
   * @param string $entityId
   *   The entity ID to check.
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The entity, when the caller already has it.
   *
   * @return bool
   *   TRUE when an active lock exists and is held by another principal.
   */
  public function conflictsForActor(string $entityType, string $entityId, ?EntityInterface $entity = NULL): bool {
    $row = $this->activeLockRow($entityType, $entityId);
    if ($row !== NULL && (int) $row['locked_by'] !== (int) $this->currentUser->id()) {
      return TRUE;
    }
    $editorial = $this->fetchEditorialLock($entity ?? $this->loadEntity($entityType, $entityId));
    return $editorial !== FALSE && (int) $editorial->uid !== (int) $this->currentUser->id();
  }

  /**
   * Whether the acting principal itself holds the active lock.
   *
   * @param string $entityType
   *   The entity type ID to check.
   * @param string $entityId
   *   The entity ID to check.
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The entity, when the caller already has it.
   *
   * @return bool
   *   TRUE when an active lock exists and the current user holds it.
   */
  public function heldByActor(string $entityType, string $entityId, ?EntityInterface $entity = NULL): bool {
    $row = $this->activeLockRow($entityType, $entityId);
    if ($row !== NULL && (int) $row['locked_by'] === (int) $this->currentUser->id()) {
      return TRUE;
    }
    $editorial = $this->fetchEditorialLock($entity ?? $this->loadEntity($entityType, $entityId));
    return $editorial !== FALSE && (int) $editorial->uid === (int) $this->currentUser->id();
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
   * Whether the Sentinel table has an active lock for this entity.
   *
   * @param string $entityType
   *   The entity type ID to check.
   * @param string $entityId
   *   The entity ID to check.
   *
   * @return bool
   *   TRUE if an active (non-expired) Sentinel lock row exists.
   */
  private function sentinelIsLocked(string $entityType, string $entityId): bool {
    $now = $this->time->getRequestTime();
    return (bool) $this->database->select('mcp_sentinel_content_locks', 'l')
      ->condition('l.entity_type', $entityType)
      ->condition('l.entity_id', $entityId)
      ->where('l.expires_at = 0 OR l.expires_at > :now', [':now' => $now])
      ->countQuery()->execute()->fetchField();
  }

  /**
   * The contrib Content Lock row, if that module holds an active lock.
   *
   * @param \Drupal\Core\Entity\EntityInterface|null $entity
   *   The entity to check, or NULL when it cannot be loaded.
   *
   * @return object{uid: int|string, timestamp?: int}|false
   *   The contrib lock object or FALSE when the module is absent, the
   *   entity is missing, or no active lock exists.
   */
  private function fetchEditorialLock(?EntityInterface $entity): object|false {
    $service = $this->editorialLock;
    if (!is_object($service) || !method_exists($service, 'fetchLock') || $entity === NULL || $entity->isNew()) {
      return FALSE;
    }
    $lock = $service->fetchLock($entity);
    return is_object($lock) ? $lock : FALSE;
  }

  /**
   * Loads an entity by id, falling back to UUID when the id does not match.
   *
   * @param string $entityType
   *   The entity type ID.
   * @param string $entityId
   *   The entity ID or UUID.
   *
   * @return \Drupal\Core\Entity\EntityInterface|null
   *   The entity, or NULL when it cannot be loaded.
   */
  private function loadEntity(string $entityType, string $entityId): ?EntityInterface {
    if ($this->entityTypeManager === NULL || $entityId === '' || !$this->entityTypeManager->hasDefinition($entityType)) {
      return NULL;
    }
    $storage = $this->entityTypeManager->getStorage($entityType);
    $entity = $storage->load($entityId);
    if ($entity instanceof EntityInterface) {
      return $entity;
    }
    if (!$storage->getEntityType()->hasKey('uuid')) {
      return NULL;
    }
    $matches = $storage->loadByProperties(['uuid' => $entityId]);
    $match = reset($matches);
    return $match instanceof EntityInterface ? $match : NULL;
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
