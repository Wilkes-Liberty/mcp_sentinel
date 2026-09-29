<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Projects an audit-chain verdict into mcp_sentinel.last_verify.
 *
 * The stored boolean is true only for the documented leading unsigned
 * prefix. A missing flag, a non-boolean, or any other reason stays a
 * critical failure when a reader classifies the stored result.
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
   * Builds the last-verify state written by Drush and Verify now.
   *
   * @param array<string, mixed> $result
   *   A verify() verdict. Only ok, broken_at, reason, and
   *   unsigned_prefix are read.
   * @param int $rows
   *   Governed-channel row count at verification time.
   * @param int $time
   *   Request time.
   *
   * @return array{ok: bool, broken_at: int|null, rows: int, time: int, reason: string|null, unsigned_prefix: bool}
   *   The state value. unsigned_prefix is true only when this verdict
   *   is the documented prefix.
   */
  public static function fromVerifyResult(array $result, int $rows, int $time): array {
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
    ];
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
