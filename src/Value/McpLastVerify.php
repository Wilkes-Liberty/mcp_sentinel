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
   * Sentinel's own verify always wins. Before the first one, a fresh Audit
   * Chain scheduled run that Audit Chain classifies as the disclosed
   * historical exception is adopted, so the dashboard does not report the
   * chain as never verified. No other scheduled verdict is adopted, and a
   * scheduled run older than a day is ignored.
   *
   * @param array<string, mixed>|null $last
   *   The mcp_sentinel.last_verify value, or NULL.
   * @param mixed $scheduled
   *   The Audit Chain scheduled-verification state value.
   * @param int $now
   *   Request time.
   *
   * @return array<string, mixed>|null
   *   The state value to classify, or NULL when there is none.
   */
  public static function effective(?array $last, mixed $scheduled, int $now): ?array {
    if ($last !== NULL && $last !== []) {
      return $last;
    }
    if (!is_array($scheduled) || !self::auditChainClassifiesHistoricalException($scheduled)) {
      return NULL;
    }
    $time = (int) ($scheduled['time'] ?? 0);
    if ($time <= 0 || $now - $time >= McpEvidenceState::STALE_AFTER) {
      return NULL;
    }
    $verdict = is_array($scheduled['verdict'] ?? NULL) ? $scheduled['verdict'] : [];
    return [
      'ok' => FALSE,
      'broken_at' => isset($verdict['broken_at']) ? (int) $verdict['broken_at'] : NULL,
      'time' => $time,
      'reason' => self::REASON_TAMPERED,
      'unsigned_prefix' => FALSE,
      'historical_exception' => TRUE,
      'source' => 'audit_chain_scheduled',
    ];
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
