<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Exception;

/**
 * Operator-facing kill-switch refusal (not the generic admit deny).
 */
final class McpKillSwitchException extends \RuntimeException {

  /**
   * Same operator account cannot confirm its own request.
   */
  public const SAME_OPERATOR = 'same_operator';

  /**
   * Confirm window has elapsed.
   */
  public const CONFIRM_EXPIRED = 'confirm_expired';

  /**
   * Target is not waiting for a second operator.
   */
  public const NOT_PENDING = 'not_pending';

  /**
   * Current account lacks administer agent kill switch.
   */
  public const PERMISSION_DENIED = 'permission_denied';

  /**
   * TTL is missing, zero, or otherwise unusable.
   */
  public const INVALID_TTL = 'invalid_ttl';

  /**
   * Selector is empty, malformed, or too long.
   */
  public const INVALID_SELECTOR = 'invalid_selector';

  /**
   * Operator account id is missing (uid 0 / empty).
   */
  public const MISSING_OPERATOR = 'missing_operator';

  /**
   * Confirm or kill lacked a Paladin or Drush-assertion identity.
   */
  public const UNVERIFIED_OPERATOR = 'unverified_operator';

  /**
   * Reason is required and must not look like a token.
   */
  public const INVALID_REASON = 'invalid_reason';

  /**
   * Confirm or status asked for an unknown batch.
   */
  public const UNKNOWN_BATCH = 'unknown_batch';

  /**
   * Kill-block table is missing; fail closed.
   */
  public const TABLE_MISSING = 'table_missing';

  /**
   * Constructs the refusal.
   *
   * @param string $reasonCode
   *   Stable machine reason.
   * @param string $message
   *   Operator-facing text. Must not contain tokens.
   */
  public function __construct(
    public readonly string $reasonCode,
    string $message,
  ) {
    parent::__construct($message);
  }

}
