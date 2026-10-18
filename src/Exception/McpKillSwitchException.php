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
   * Mixed-channel confirm with no bound operator record.
   */
  public const UNBOUND_OPERATOR = 'unbound_operator';

  /**
   * Identities already belong to different operator records.
   */
  public const OPERATOR_BINDING_CONFLICT = 'operator_binding_conflict';

  /**
   * The --operator option does not match the bound Drupal account.
   */
  public const OPERATOR_MISMATCH = 'operator_mismatch';

  /**
   * Paladin introspection is unreachable or not configured.
   */
  public const PALADIN_UNAVAILABLE = 'paladin_unavailable';

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
   * Break-glass action is not keep, extend, or lift.
   */
  public const INVALID_ACTION = 'invalid_action';

  /**
   * Target is not an active mass freeze.
   */
  public const NOT_FROZEN = 'not_frozen';

  /**
   * Held delivery row is missing or not in a held state.
   */
  public const NOT_HELD = 'not_held';

  /**
   * Release is refused while the delivery scope is still stopped.
   */
  public const SCOPE_STOPPED = 'scope_stopped';

  /**
   * Break-glass is limited to the identity in settings.php.
   */
  public const BREAK_GLASS_DENIED = 'break_glass_denied';

  /**
   * Constructs the refusal.
   *
   * @param string $reasonCode
   *   Stable machine reason.
   * @param string $message
   *   Operator-facing text. Must not contain tokens.
   */
  /**
   * Whether auditOperatorRefusal() has already recorded this refusal.
   */
  public bool $audited = FALSE;

  public function __construct(
    public readonly string $reasonCode,
    string $message,
  ) {
    parent::__construct($message);
  }

}
