<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Typed reader for a stored kill-block expiry.
 *
 * Production implements this. A decorator may only veto: NULL is
 * unreadable (still blocking). Production ignores a seam timestamp
 * so a decorator cannot expire a live block.
 */
interface McpKillBlockUntilReaderInterface {

  /**
   * Unix timestamp from a kill-block row, or NULL when unreadable.
   *
   * Callers treat NULL as still blocking. Returning an int does
   * not expire the block; production parses the stored value.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   */
  public function read(array $row): ?int;

}
