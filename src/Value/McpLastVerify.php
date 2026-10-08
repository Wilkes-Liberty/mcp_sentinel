<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\audit_chain\ScheduledVerificationIntegrity;
use Drupal\mcp_sentinel\Enum\McpEvidenceState;

/**
 * Projects an audit-chain verdict into mcp_sentinel.last_verify.
 *
 * Two failed verdicts are documented exceptions rather than tampering: the
 * leading unsigned prefix, and a disclosed historical exception whose
 * recovery successor verifies. Each stored boolean is true only for its
 * case. A missing flag, a non-boolean, or any other reason stays a critical
 * failure when a reader classifies the stored result.
 */
final class McpLastVerify {

  /**
   * Audit Chain reason for rows hashed without the signing key.
   *
   * Matches AuditChainLogger::REASON_WRITTEN_UNKEYED. Compared as a
   * string so a verdict that never carries the prefix flag still
   * classifies as a critical failure.
   */
  public const REASON_WRITTEN_UNKEYED = 'written_unkeyed';

  /**
   * Audit Chain reason for a row whose hash or link does not verify.
   *
   * Matches AuditChainLogger::REASON_TAMPERED.
   */
  public const REASON_TAMPERED = 'tampered';

  /**
   * State key of Audit Chain's scheduled verification run.
   *
   * Matches ScheduledVerifier::STATE_KEY.
   */
  public const SCHEDULED_STATE_KEY = 'audit_chain.scheduled_verification';

  /**
   * Successor reason Audit Chain stores when a segment is first activated.
   */
  private const REASON_AWAITING_VERIFICATION = 'awaiting_verification';

  /**
   * Builds the last-verify state written by Drush and Verify now.
   *
   * @param array<string, mixed> $result
   *   A verify() verdict. ok, broken_at, reason and unsigned_prefix are
   *   stored. The whole verdict is passed to Audit Chain's classifier.
   * @param int $rows
   *   Governed-channel row count at verification time.
   * @param int $time
   *   Request time.
   * @param array<string, mixed>|null $successor
   *   Audit Chain's recovery successor status, read in the same request,
   *   or NULL when there is no successor or Audit Chain cannot report one.
   *
   * @return array{ok: bool, broken_at: int|null, rows: int, time: int, reason: string|null, unsigned_prefix: bool, historical_exception: bool}
   *   The state value. unsigned_prefix and historical_exception are true
   *   only when this verdict is that documented exception.
   */
  public static function fromVerifyResult(array $result, int $rows, int $time, ?array $successor = NULL): array {
    $reason = isset($result['reason']) && is_string($result['reason']) && $result['reason'] !== ''
      ? $result['reason']
      : NULL;
    $projected = [
      'ok' => $result['ok'] ?? NULL,
      'reason' => $reason,
      'unsigned_prefix' => $result['unsigned_prefix'] ?? FALSE,
    ];
    return [
      'ok' => (bool) ($result['ok'] ?? FALSE),
      'broken_at' => isset($result['broken_at']) ? (int) $result['broken_at'] : NULL,
      'rows' => $rows,
      'time' => $time,
      'reason' => $reason,
      'unsigned_prefix' => self::isDocumentedUnsignedPrefix($projected),
      'historical_exception' => self::auditChainClassifiesHistoricalException([
        'ok' => $result['ok'] ?? NULL,
        'reason' => $reason,
        'verdict' => $result,
        'successor' => $successor,
      ]),
    ];
  }

  /**
   * Whether stored last-verify state is the disclosed historical exception.
   *
   * True only when verification failed as tampered and the flag stored at
   * verification time is strictly TRUE. Staleness is the reader's concern:
   * see McpEvidenceState::fromLastVerify().
   *
   * @param array<string, mixed>|null $last
   *   The mcp_sentinel.last_verify value, or NULL.
   *
   * @return bool
   *   TRUE when the stored result is the documented historical exception.
   */
  public static function isDocumentedHistoricalException(?array $last): bool {
    return is_array($last)
      && ($last['ok'] ?? NULL) === FALSE
      && ($last['historical_exception'] ?? FALSE) === TRUE
      && ($last['reason'] ?? NULL) === self::REASON_TAMPERED;
  }

  /**
   * Returns the last-verify state readers should classify.
   *
   * Sentinel's own verify wins, with one exception: a stored historical
   * exception does not survive a newer Audit Chain scheduled run that finds
   * tampering it does not classify as that exception. Tampering adds no
   * rows, so the stored verify would otherwise keep explaining a new break
   * until it aged out. The placeholder Audit Chain writes when a segment is
   * activated is not such a run: it carries no successor verdict yet.
   *
   * A fresh scheduled run that Audit Chain classifies as the disclosed
   * historical exception is adopted in two cases: before the first Sentinel
   * verify, so the dashboard does not report the chain as never verified,
   * and when it is newer than a stored historical exception, so governed
   * traffic after a manual verify does not leave the chain reported as
   * stale while Audit Chain keeps confirming the same exception. A stored
   * verify that is not the historical exception is never replaced this way,
   * so a break Sentinel saw itself stays critical until an operator verifies
   * again. No other scheduled verdict is adopted, and a scheduled run older
   * than a day is ignored. The adopted value's row baseline is the governed
   * rows stamped at or before the run, so later rows make it stale. A row
   * written later in the same second as the run is caught by the next row
   * after it.
   *
   * @param array<string, mixed>|null $last
   *   The mcp_sentinel.last_verify value, or NULL.
   * @param mixed $scheduled
   *   The Audit Chain scheduled-verification state value.
   * @param int $now
   *   Request time.
   * @param \Closure(int): int $governedRowsThrough
   *   Counts governed-channel audit rows stamped at or before a time.
   *   Called only when a scheduled run is adopted.
   * @param int $staleAfter
   *   Seconds after which a scheduled run is too old to adopt; the site's
   *   evidence_stale_after setting.
   *
   * @return array<string, mixed>|null
   *   The state value to classify, or NULL when there is none.
   */
  public static function effective(?array $last, mixed $scheduled, int $now, \Closure $governedRowsThrough, int $staleAfter = McpEvidenceState::STALE_AFTER): ?array {
    if ($last !== NULL && $last !== []) {
      if (self::isDocumentedHistoricalException($last)
        && is_array($scheduled)
        && (int) ($scheduled['time'] ?? 0) > (int) ($last['time'] ?? 0)
        && ($scheduled['ok'] ?? NULL) === FALSE
        && ($scheduled['reason'] ?? NULL) === self::REASON_TAMPERED
        && !self::awaitsSuccessorVerification($scheduled)
        && !self::auditChainClassifiesHistoricalException($scheduled)) {
        $verdict = is_array($scheduled['verdict'] ?? NULL) ? $scheduled['verdict'] : [];
        return [
          'ok' => FALSE,
          'broken_at' => isset($verdict['broken_at']) ? (int) $verdict['broken_at'] : NULL,
          'time' => (int) $scheduled['time'],
          'reason' => self::REASON_TAMPERED,
          'unsigned_prefix' => FALSE,
          'historical_exception' => FALSE,
          'source' => 'audit_chain_scheduled',
        ];
      }
      if (self::isDocumentedHistoricalException($last)
        && is_array($scheduled)
        && (int) ($scheduled['time'] ?? 0) > (int) ($last['time'] ?? 0)) {
        return self::adoptHistoricalException($scheduled, $now, $governedRowsThrough, $staleAfter) ?? $last;
      }
      return $last;
    }
    return is_array($scheduled) ? self::adoptHistoricalException($scheduled, $now, $governedRowsThrough, $staleAfter) : NULL;
  }

  /**
   * Adopts a fresh scheduled run Audit Chain classifies as the exception.
   *
   * @param array<string, mixed> $scheduled
   *   The Audit Chain scheduled-verification state value.
   * @param int $now
   *   Request time.
   * @param \Closure(int): int $governedRowsThrough
   *   Counts governed-channel audit rows stamped at or before a time.
   * @param int $staleAfter
   *   Seconds after which the run is too old to adopt.
   *
   * @return array<string, mixed>|null
   *   The adopted state value, or NULL when the run is not the documented
   *   historical exception or is older than the configured age.
   */
  private static function adoptHistoricalException(array $scheduled, int $now, \Closure $governedRowsThrough, int $staleAfter): ?array {
    if (!self::auditChainClassifiesHistoricalException($scheduled)) {
      return NULL;
    }
    $time = (int) ($scheduled['time'] ?? 0);
    if ($time <= 0 || $now - $time >= $staleAfter) {
      return NULL;
    }
    $verdict = is_array($scheduled['verdict'] ?? NULL) ? $scheduled['verdict'] : [];
    return [
      'ok' => FALSE,
      'broken_at' => isset($verdict['broken_at']) ? (int) $verdict['broken_at'] : NULL,
      'rows' => $governedRowsThrough($time),
      'time' => $time,
      'reason' => self::REASON_TAMPERED,
      'unsigned_prefix' => FALSE,
      'historical_exception' => TRUE,
      'source' => 'audit_chain_scheduled',
    ];
  }

  /**
   * Whether a scheduled run is Audit Chain's post-activation placeholder.
   *
   * @param array<string, mixed> $run
   *   The Audit Chain scheduled-verification state value.
   *
   * @return bool
   *   TRUE when the successor has not been verified by a scheduled run yet.
   */
  private static function awaitsSuccessorVerification(array $run): bool {
    $successor = $run['successor'] ?? NULL;
    return is_array($successor)
      && ($successor['reason'] ?? NULL) === self::REASON_AWAITING_VERIFICATION;
  }

  /**
   * Asks Audit Chain whether a run is its documented historical exception.
   *
   * Audit Chain owns the definition: a tampered verdict whose break is the
   * disclosed row, with a successor segment that verifies. Versions without
   * recovery segments cannot classify it, so the answer there is FALSE and
   * the failure stays critical.
   *
   * @param array<string, mixed> $run
   *   ok, reason, verdict and successor, in Audit Chain's run shape.
   *
   * @return bool
   *   TRUE only when Audit Chain classifies the run as that exception.
   */
  private static function auditChainClassifiesHistoricalException(array $run): bool {
    if (($run['ok'] ?? NULL) !== FALSE) {
      return FALSE;
    }
    // The classifier only exists in newer Audit Chain releases. Static
    // analysis sees whichever version is installed.
    // @phpstan-ignore function.alreadyNarrowedType
    if (!method_exists(ScheduledVerificationIntegrity::class, 'isDocumentedHistoricalException')) {
      return FALSE;
    }
    return ScheduledVerificationIntegrity::isDocumentedHistoricalException($run);
  }

  /**
   * Whether stored last-verify state is the documented unsigned prefix.
   *
   * True only when verification failed, unsigned_prefix is strictly
   * TRUE, and reason is written_unkeyed.
   *
   * @param array<string, mixed>|null $last
   *   The mcp_sentinel.last_verify value, or NULL.
   *
   * @return bool
   *   TRUE when the stored result is the documented prefix.
   */
  public static function isDocumentedUnsignedPrefix(?array $last): bool {
    return is_array($last)
      && ($last['ok'] ?? NULL) === FALSE
      && ($last['unsigned_prefix'] ?? FALSE) === TRUE
      && ($last['reason'] ?? NULL) === self::REASON_WRITTEN_UNKEYED;
  }

}
