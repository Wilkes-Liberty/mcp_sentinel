<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Strict readers for mixed stored and config values.
 *
 * Unreadable values are '' or 0. Callers that enforce on a
 * missing or corrupt field must treat those as blocking (hold
 * a keyless row, refuse an unknown kill status, or keep a
 * NULL block_until in force). stringKeyedRow() returns NULL
 * when the value is not an array or a key is not a string.
 */
final class McpStoredValue {

  /**
   * String from a mixed stored or config value.
   *
   * @param mixed $value
   *   Stored or config value.
   *
   * @return string
   *   The value as a string, or empty when it is not a
   *   string or number.
   */
  public static function string(mixed $value): string {
    if (is_string($value)) {
      return $value;
    }
    if (is_int($value) || is_float($value)) {
      return (string) $value;
    }
    return '';
  }

  /**
   * Integer from a mixed stored or config value.
   *
   * Bool, array, object, and NULL are unreadable (0). A
   * numeric string or float is truncated toward zero.
   *
   * @param mixed $value
   *   Stored or config value.
   *
   * @return int
   *   The value as an int, or 0 when it is not numeric.
   */
  public static function int(mixed $value): int {
    if (is_int($value)) {
      return $value;
    }
    if (is_string($value) && is_numeric($value)) {
      return (int) $value;
    }
    if (is_float($value)) {
      return (int) $value;
    }
    return 0;
  }

  /**
   * String field from a stored row.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   * @param string $key
   *   Column name.
   */
  public static function rowString(array $row, string $key): string {
    return self::string($row[$key] ?? '');
  }

  /**
   * Integer field from a stored row. Unreadable values are 0.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   * @param string $key
   *   Column name.
   */
  public static function rowInt(array $row, string $key): int {
    return self::int($row[$key] ?? NULL);
  }

  /**
   * String-keyed row from a fetchAssoc() result.
   *
   * @return array<string, mixed>|null
   *   The row, or NULL when the result is missing or not
   *   string-keyed. Enforcement treats NULL as blocking.
   */
  public static function stringKeyedRow(mixed $row): ?array {
    if (!is_array($row)) {
      return NULL;
    }
    $typed = [];
    foreach ($row as $key => $value) {
      if (!is_string($key)) {
        return NULL;
      }
      $typed[$key] = $value;
    }
    return $typed;
  }

}
