<?php

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Session\AccountProxyInterface;

/**
 * Manages content locks that block MCP writes to human-edited content.
 */
class McpContentLock {

  private const DEFAULT_TTL = 3600;

  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Lock an entity against MCP writes.
   */
  public function lock(string $entityType, string $entityId, string $reason = '', ?int $ttl = self::DEFAULT_TTL): void {
    $now = $this->time->getRequestTime();
    $this->database->merge('mcp_sentinel_content_locks')
      ->keys(['entity_type' => $entityType, 'entity_id' => $entityId])
      ->fields([
        'locked_by'  => $this->currentUser->id(),
        'locked_at'  => $now,
        'expires_at' => $ttl ? ($now + $ttl) : 0,
        'reason'     => substr($reason, 0, 512),
      ])
      ->execute();
  }

  /**
   * Release a lock on an entity.
   */
  public function release(string $entityType, string $entityId): void {
    $this->database->delete('mcp_sentinel_content_locks')
      ->condition('entity_type', $entityType)
      ->condition('entity_id', $entityId)
      ->execute();
  }

  /**
   * Check whether an entity is currently locked against MCP writes.
   *
   * Expired locks are excluded by a query condition rather than deleted, so a
   * read never writes. Expired rows are reaped by hook_cron via
   * releaseExpired().
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
   * Returns lock details or NULL if not locked.
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
   * Releases all expired locks. Called by hook_cron.
   */
  public function releaseExpired(): int {
    $now = $this->time->getRequestTime();
    return (int) $this->database->delete('mcp_sentinel_content_locks')
      ->condition('expires_at', 0, '>')
      ->condition('expires_at', $now, '<')
      ->execute();
  }

}
