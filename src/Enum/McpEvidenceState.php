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
   * Default age after which a verify is stale even if the row count matches.
   *
   * Sites set their own value in mcp_sentinel.settings:evidence_stale_after
   * (d.o #3629250). This constant is the default and the fallback.
   */
  public const STALE_AFTER = 86400;

  /**
   * Smallest configurable age, so evidence cannot be set to expire at once.
   */
  public const MIN_STALE_AFTER = 300;

  /**
   * Normalizes configured staleness thresholds.
   *
   * @param mixed $staleAfter
   *   The configured evidence_stale_after value, or NULL when unset.
   * @param mixed $staleRows
   *   The configured evidence_stale_rows value, or NULL when unset.
   *
   * @return array{0: int, 1: int}
   *   Seconds (never below MIN_STALE_AFTER) and tolerated new rows (never
   *   below 0). A missing or non-numeric value falls back to the default.
   */
  public static function thresholds(mixed $staleAfter, mixed $staleRows): array {
    $after = is_numeric($staleAfter) ? max(self::MIN_STALE_AFTER, (int) $staleAfter) : self::STALE_AFTER;
    $rows = is_numeric($staleRows) ? max(0, (int) $staleRows) : 0;
    return [$after, $rows];
  }

  /**
   * Classifies stored last-verify state against the live audit row count.
   *
   * @param array<string, mixed>|null $last
   *   The mcp_sentinel.last_verify state value, or NULL when never written.
   * @param int $currentRows
   *   Current audit-chain row count on the governed channels.
   * @param int $now
   *   Request time, for the stale-age check.
   * @param int $staleAfter
   *   Seconds after which a verify is stale.
   * @param int $staleRows
   *   Governed rows that may land after a verify before it is stale. 0 means
   *   any new row makes it stale.
   */
  public static function fromLastVerify(?array $last, int $currentRows, int $now, int $staleAfter = self::STALE_AFTER, int $staleRows = 0): self {
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
      // verified against. Once it ages out or more new rows land than the
      // site tolerates, a new break may sit behind it, so it reads as stale
      // rather than as explained.
      if (McpLastVerify::isDocumentedHistoricalException($last)
        && self::isStale($last, $currentRows, $now, $staleAfter, $staleRows)) {
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
    return self::isStale($last, $currentRows, $now, $staleAfter, $staleRows) ? self::Stale : self::Verified;
  }

  /**
   * Whether a stored verdict is too old, or too many audit rows postdate it.
   *
   * @param array<string, mixed> $last
   *   The mcp_sentinel.last_verify state value.
   * @param int $currentRows
   *   Current audit-chain row count on the governed channels.
   * @param int $now
   *   Request time.
   * @param int $staleAfter
   *   Seconds after which the verdict is stale.
   * @param int $staleRows
   *   New governed rows tolerated before the verdict is stale.
   */
  private static function isStale(array $last, int $currentRows, int $now, int $staleAfter, int $staleRows): bool {
    $verifiedAt = isset($last['time']) ? (int) $last['time'] : 0;
    if ($verifiedAt <= 0 || $now - $verifiedAt >= $staleAfter) {
      return TRUE;
    }
    $verifiedRows = array_key_exists('rows', $last) ? (int) $last['rows'] : -1;
    return $verifiedRows >= 0 && $currentRows - $verifiedRows > $staleRows;
  }

  /**
   * Whether this state may contribute to an overall clear posture.
   */
  public function allowsClear(): bool {
    return $this === self::Verified;
  }

}
