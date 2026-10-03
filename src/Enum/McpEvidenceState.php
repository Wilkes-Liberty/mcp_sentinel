<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

use Drupal\mcp_sentinel\Value\McpLastVerify;

/**
 * Evidence-verification states the dashboard must keep distinct (d.o #3616611).
 *
 * Only Verified may contribute to an overall clear posture. Every other
 * state is a non-clear reason the operator can act on.
 */
enum McpEvidenceState: string {

  case Unknown = 'unknown';
  case Pending = 'pending';
  case Verified = 'verified';
  case Stale = 'stale';
  case Degraded = 'degraded';
  case Failed = 'failed';
  case Unavailable = 'unavailable';

  /**
   * Age after which a successful verify is stale even if the row count matches.
   */
  public const STALE_AFTER = 86400;

  /**
   * Classifies stored last-verify state against the live audit row count.
   *
   * @param array<string, mixed>|null $last
   *   The mcp_sentinel.last_verify state value, or NULL when never written.
   * @param int $currentRows
   *   Current audit-chain row count on the governed channels.
   * @param int $now
   *   Request time, for the stale-age check.
   */
  public static function fromLastVerify(?array $last, int $currentRows, int $now): self {
    if ($last === NULL || $last === []) {
      return $currentRows > 0 ? self::Pending : self::Unknown;
    }
    if (!empty($last['error'])) {
      return self::Unavailable;
    }
    if (!array_key_exists('ok', $last)) {
      return self::Degraded;
    }
    if ($last['ok'] === FALSE) {
      // A disclosed historical exception explains only the chain it was
      // verified against. Once it ages out or new rows land, a new break may
      // sit behind it, so it reads as stale rather than as explained.
      if (McpLastVerify::isDocumentedHistoricalException($last)
        && self::isStale($last, $currentRows, $now)) {
        return self::Stale;
      }
      return self::Failed;
    }
    if ($last['ok'] !== TRUE) {
      return self::Degraded;
    }
    $verifiedAt = isset($last['time']) ? (int) $last['time'] : 0;
    if ($verifiedAt <= 0) {
      return self::Degraded;
    }
    return self::isStale($last, $currentRows, $now) ? self::Stale : self::Verified;
  }

  /**
   * Whether a stored verdict is too old, or predates new audit rows.
   *
   * @param array<string, mixed> $last
   *   The mcp_sentinel.last_verify state value.
   * @param int $currentRows
   *   Current audit-chain row count on the governed channels.
   * @param int $now
   *   Request time.
   */
  private static function isStale(array $last, int $currentRows, int $now): bool {
    $verifiedAt = isset($last['time']) ? (int) $last['time'] : 0;
    if ($verifiedAt <= 0 || $now - $verifiedAt >= self::STALE_AFTER) {
      return TRUE;
    }
    $verifiedRows = array_key_exists('rows', $last) ? (int) $last['rows'] : -1;
    return $verifiedRows >= 0 && $currentRows > $verifiedRows;
  }

  /**
   * Whether this state may contribute to an overall clear posture.
   */
  public function allowsClear(): bool {
    return $this === self::Verified;
  }

}
