<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Exception\McpKillSwitchException;

/**
 * Kill-block TTL bounds (DEV-846, operator-approved).
 *
 * Default 24 h, maximum 7 d. A requested or configured TTL above
 * 7 d is a validation error. The maximum cannot be configured
 * upward. Re-killing may extend block_until up to 7 d from now.
 */
final class McpKillTtl {

  /**
   * Default kill-block lifetime in seconds (24 h).
   */
  public const DEFAULT = 86400;

  /**
   * Maximum kill-block lifetime in seconds (7 d).
   */
  public const MAX = 604800;

  /**
   * Default two-person confirm window in seconds (15 min).
   */
  public const CONFIRM_WINDOW_DEFAULT = 900;

  /**
   * Resolves a requested TTL against the configured default and cap.
   *
   * Does not clamp. Values above 7 d, or above the configured max
   * when that max is at most 7 d, are refused.
   *
   * @param int|null $requested
   *   Seconds requested by the operator, or NULL for the default.
   * @param int $default
   *   Configured default (usually DEFAULT). Must not exceed MAX.
   * @param int $max
   *   Configured maximum. Must not exceed MAX.
   *
   * @return int
   *   Seconds that will actually be applied.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the value is not a positive lifetime at or below 7 d.
   */
  public static function resolve(?int $requested, int $default = self::DEFAULT, int $max = self::MAX): int {
    if ($max > self::MAX || $default > self::MAX) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL cannot exceed 7 days.',
      );
    }
    if ($max <= 0 || $default <= 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL must be a positive number of seconds.',
      );
    }
    $ttl = $requested ?? $default;
    if ($ttl <= 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL must be a positive number of seconds.',
      );
    }
    if ($ttl > self::MAX || $ttl > $max) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL cannot exceed 7 days.',
      );
    }
    return $ttl;
  }

  /**
   * Absolute block_until timestamp from now.
   */
  public static function blockUntil(int $now, int $ttl): int {
    return $now + $ttl;
  }

}
