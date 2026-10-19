<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Typed reader for a stored kill-block expiry.
 *
 * Drupal 11.3 stringifies integers on every driver. An unreadable
 * value fails closed (NULL). Tests decorate this service; production
 * treats a NULL read as a veto and ignores a seam timestamp.
 */
final class McpKillBlockUntilReader implements McpKillBlockUntilReaderInterface {

  /**
   * Unix timestamp from a kill-block row, or NULL when unreadable.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   */
  public function read(array $row): ?int {
    $value = $row['block_until'] ?? NULL;
    if (is_int($value)) {
      return $value;
    }
    if (is_string($value) && is_numeric($value)) {
      return (int) $value;
    }
    return NULL;
  }

}
