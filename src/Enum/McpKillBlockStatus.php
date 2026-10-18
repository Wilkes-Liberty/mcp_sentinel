<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Durable kill-block row states (DEV-846, DEV-985).
 *
 * A kill_pending row is an active mass freeze: in-scope agents are
 * refused immediately. A distinct second operator confirms, extends,
 * or lifts it. The confirm window never lifts the freeze. An
 * unconfirmed freeze also stays frozen after block_until until two
 * operators lift it or break-glass is used. Confirmed stops still
 * expire at their TTL. An unkill_pending row stays refused until
 * a distinct bound operator confirms the lift.
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
      self::KillPending => TRUE,
      self::Expired => FALSE,
    };
  }

}
