<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Typed reader for a stored kill-block expiry.
 *
 * Production implements this. Tests decorate the service.
 */
interface McpKillBlockUntilReaderInterface {

  /**
   * Unix timestamp from a kill-block row, or NULL when unreadable.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   */
  public function read(array $row): ?int;

}
