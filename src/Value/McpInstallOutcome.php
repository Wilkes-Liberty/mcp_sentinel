<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Check-outcome vocabulary for the install verifier (#112 / d.o #3616537).
 *
 * `skipped` and `n/a` are deliberately different. A check that SHOULD have
 * run and could not is `skipped`, and a skipped check fails the run —
 * silence is not evidence. A check that does not apply to this shape of
 * install is `n/a` and does not fail it: a verifier a secure install can
 * never pass is a verifier people stop running.
 */
final class McpInstallOutcome {

  /**
   * The check ran and found nothing wrong.
   */
  public const PASS = 'pass';

  /**
   * The check ran and found a problem.
   */
  public const FAIL = 'fail';

  /**
   * The check should have run and could not.
   */
  public const SKIPPED = 'skipped';

  /**
   * The check does not apply to this install shape.
   */
  public const NOT_APPLICABLE = 'n/a';

  /**
   * Whether this status fails the overall run.
   *
   * @param string $status
   *   One of the outcome constants.
   *
   * @return bool
   *   TRUE for fail and skipped.
   */
  public static function failsRun(string $status): bool {
    return $status === self::FAIL || $status === self::SKIPPED;
  }

}
