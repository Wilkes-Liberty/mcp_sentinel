<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Keeps flood event names within the database backend's 64-byte contract.
 */
final class McpFloodKey {

  /**
   * Preserves valid legacy keys and hashes only names that cannot fit.
   */
  public static function normalize(string $key): string {
    return strlen($key) <= 64 ? $key : 'mcps.' . substr(hash('sha256', $key), 0, 59);
  }

}
