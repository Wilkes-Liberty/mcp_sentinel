<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Exception\McpKillSwitchException;

/**
 * Kill-block TTL bounds (DEV-846, operator-approved).
 *
 * Default 24 h, maximum 7 d. Re-killing extends block_until up to
 * the maximum from now.
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
   * @param int|null $requested
   *   Seconds requested by the operator, or NULL for the default.
   * @param int $default
   *   Configured default (usually DEFAULT).
   * @param int $max
   *   Configured maximum (usually MAX).
   *
   * @return int
   *   Seconds that will actually be applied, never above $max.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the resolved value is not a positive lifetime.
   */
  public static function resolve(?int $requested, int $default = self::DEFAULT, int $max = self::MAX): int {
    $ttl = $requested ?? $default;
    if ($ttl <= 0) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_TTL,
        'Kill-block TTL must be a positive number of seconds.',
      );
    }
    $max = max(1, $max);
    return min($ttl, $max);
  }

  /**
   * Absolute block_until timestamp from now.
   */
  public static function blockUntil(int $now, int $ttl): int {
    return $now + $ttl;
  }

}
