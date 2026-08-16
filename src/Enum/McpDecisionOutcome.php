<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Stable decision outcomes for a governed action.
 *
 * The backed value is the contract. Prose around a case is only a hint.
 * Slice 1 of #3616538 ships the vocabulary dark: no production path
 * requires a sealed manifest.
 */
enum McpDecisionOutcome: string {

  case Deny = 'deny';
  case Allow = 'allow';
  case RequireApproval = 'require_approval';
  case AllowWithObligations = 'allow_with_obligations';

  /**
   * Whether this outcome permits the action to proceed now.
   *
   * Allow-with-obligations is still a permit. The caller must honour
   * the obligations; it does not turn the outcome into a deny.
   */
  public function isPermitted(): bool {
    return $this === self::Allow || $this === self::AllowWithObligations;
  }

  /**
   * Whether this outcome may carry an obligations list.
   */
  public function allowsObligations(): bool {
    return $this === self::AllowWithObligations;
  }

}
