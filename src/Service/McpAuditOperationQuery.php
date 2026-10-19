<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\SelectInterface;
use Drupal\mcp_sentinel\Value\McpStoredValue;

/**
 * Shared audit-log query for an anomaly operation pattern in a window.
 *
 * Match semantics are the same as McpAnomalyDetector: exact `=` unless the
 * pattern ends with `*`, which is a prefix LIKE. Queries the indexed
 * `operation` and `timestamp` columns only.
 */
final class McpAuditOperationQuery {

  /**
   * Builds a select for matching audit rows newer than $since.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param string $pattern
   *   Operation pattern (trailing `*` enables prefix match).
   * @param int $since
   *   Exclusive lower bound on `timestamp`.
   *
   * @return \Drupal\Core\Database\Query\SelectInterface
   *   An unbound select on `audit_chain_log` alias `l`.
   */
  public static function selectMatching(
    Connection $database,
    string $pattern,
    int $since,
  ): SelectInterface {
    $query = $database
      ->select('audit_chain_log', 'l')
      ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
      ->condition('l.timestamp', $since, '>');
    self::applyPattern($query, $database, $pattern);
    return $query;
  }

  /**
   * Counts matching audit rows newer than $since.
   *
   * Same conditions as selectMatching(), with no scan cap.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param string $pattern
   *   Operation pattern (trailing `*` enables prefix match).
   * @param int $since
   *   Exclusive lower bound on `timestamp`.
   *
   * @return int
   *   Matching row count.
   */
  public static function countMatching(
    Connection $database,
    string $pattern,
    int $since,
  ): int {
    $statement = self::selectMatching($database, $pattern, $since)
      ->countQuery()
      ->execute();
    if ($statement === NULL) {
      return 0;
    }
    return McpStoredValue::int($statement->fetchField());
  }

  /**
   * Applies the operation-pattern condition to an existing select.
   *
   * @param \Drupal\Core\Database\Query\SelectInterface $query
   *   Query already aliased as `l`.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection (LIKE escaping).
   * @param string $pattern
   *   Operation pattern.
   */
  public static function applyPattern(
    SelectInterface $query,
    Connection $database,
    string $pattern,
  ): void {
    if (str_ends_with($pattern, '*')) {
      $prefix = substr($pattern, 0, -1);
      $query->condition(
        'l.operation',
        $database->escapeLike($prefix) . '%',
        'LIKE',
      );
      return;
    }
    $query->condition('l.operation', $pattern);
  }

}
