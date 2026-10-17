<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Durable kill-block row states (DEV-846, DEV-985).
 *
 * kill_pending is an active mass freeze: in-scope agents are refused
 * immediately. A distinct second operator confirms, extends, or lifts
 * it. The confirm window never lifts the freeze; expiry of
 * block_until still follows the 24 h / 7 d kill-block policy.
 * unkill_pending stays refused until the named second person
 * (secondary account holder) confirms the lift.
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
      self::Killed, self::UnkillPending, self::KillPending => $blockUntil > $now,
      self::Expired => FALSE,
    };
  }

}
