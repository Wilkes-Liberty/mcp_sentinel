<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Enum\McpDecisionOutcome;
use Drupal\mcp_sentinel\Enum\McpDecisionReason;

/**
 * Immutable typed decision for a governed action.
 *
 * Outcome plus one stable reason, and an obligations list that is
 * valid only on allow_with_obligations. Ships dark in slice 1 of
 * #3616538: existing call sites keep returning bools.
 */
final class McpDecision {

  /**
   * Obligation codes, in caller order.
   *
   * @var list<string>
   */
  private readonly array $obligations;

  /**
   * Constructs a decision.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionOutcome $outcome
   *   The outcome.
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionReason $reason
   *   The stable reason code.
   * @param array $obligations
   *   Obligation codes. Each must be a non-empty string. Non-empty
   *   only when the outcome is allow_with_obligations.
   */
  private function __construct(
    private readonly McpDecisionOutcome $outcome,
    private readonly McpDecisionReason $reason,
    array $obligations,
  ) {
    $normalized = [];
    foreach ($obligations as $index => $obligation) {
      if (!is_string($obligation) || trim($obligation) === '') {
        throw new \InvalidArgumentException(sprintf(
          'Obligation at offset %s must be a non-empty string.',
          (string) $index,
        ));
      }
      $normalized[] = $obligation;
    }
    if ($outcome->allowsObligations()) {
      if ($normalized === []) {
        throw new \InvalidArgumentException(
          'allow_with_obligations requires at least one obligation.',
        );
      }
    }
    elseif ($normalized !== []) {
      throw new \InvalidArgumentException(sprintf(
        'Obligations are only valid on allow_with_obligations, not %s.',
        $outcome->value,
      ));
    }
    $this->obligations = $normalized;
  }

  /**
   * Creates a deny decision.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionReason $reason
   *   Why the action is denied.
   *
   * @return self
   *   The decision.
   */
  public static function deny(McpDecisionReason $reason): self {
    return new self(McpDecisionOutcome::Deny, $reason, []);
  }

  /**
   * Creates an allow decision.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionReason $reason
   *   Why the action is allowed without obligations.
   *
   * @return self
   *   The decision.
   */
  public static function allow(McpDecisionReason $reason): self {
    return new self(McpDecisionOutcome::Allow, $reason, []);
  }

  /**
   * Creates a require-approval decision.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionReason $reason
   *   Why approval is required.
   *
   * @return self
   *   The decision.
   */
  public static function requireApproval(McpDecisionReason $reason): self {
    return new self(McpDecisionOutcome::RequireApproval, $reason, []);
  }

  /**
   * Creates an allow-with-obligations decision.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpDecisionReason $reason
   *   Why the action is allowed only with obligations.
   * @param string[] $obligations
   *   Non-empty list of stable obligation codes.
   *
   * @return self
   *   The decision.
   */
  public static function allowWithObligations(
    McpDecisionReason $reason,
    array $obligations,
  ): self {
    return new self(
      McpDecisionOutcome::AllowWithObligations,
      $reason,
      $obligations,
    );
  }

  /**
   * The outcome.
   */
  public function outcome(): McpDecisionOutcome {
    return $this->outcome;
  }

  /**
   * The stable reason code.
   */
  public function reason(): McpDecisionReason {
    return $this->reason;
  }

  /**
   * Obligation codes. Empty unless the outcome is allow_with_obligations.
   *
   * @return list<string>
   *   Obligation codes in caller order.
   */
  public function obligations(): array {
    return $this->obligations;
  }

  /**
   * Whether the action is denied.
   */
  public function isDenied(): bool {
    return $this->outcome === McpDecisionOutcome::Deny;
  }

  /**
   * Whether the action may proceed now.
   *
   * True for allow and allow_with_obligations.
   */
  public function isAllowed(): bool {
    return $this->outcome->isPermitted();
  }

  /**
   * Whether a human must approve before execution.
   */
  public function requiresApproval(): bool {
    return $this->outcome === McpDecisionOutcome::RequireApproval;
  }

  /**
   * Whether the decision carries obligations.
   */
  public function hasObligations(): bool {
    return $this->obligations !== [];
  }

  /**
   * Stable array form. Never contains secrets.
   *
   * @return array{outcome: string, reason: string, obligations: list<string>}
   *   The decision as scalar values.
   */
  public function toArray(): array {
    return [
      'outcome' => $this->outcome->value,
      'reason' => $this->reason->value,
      'obligations' => $this->obligations,
    ];
  }

}
