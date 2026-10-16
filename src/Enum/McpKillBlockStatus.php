<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Durable kill-block row states (DEV-846).
 *
 * Access is restored when the row is expired or removed. unkill_pending
 * stays refused until the named second person (secondary account
 * holder) confirms.
 */
enum McpKillBlockStatus: string {

  case Killed = 'killed';
  case KillPending = 'kill_pending';
  case UnkillPending = 'unkill_pending';
  case Expired = 'expired';

  /**
   * Whether this state currently refuses the principal.
   */
  public function isBlocking(int $blockUntil, int $now): bool {
    return match ($this) {
      self::Killed, self::UnkillPending => $blockUntil > $now,
      self::KillPending, self::Expired => FALSE,
    };
  }

}
