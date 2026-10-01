<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Operator- and agent-facing explanation of a policy denial.
 *
 * Never carries secrets. Widening is advisory only: callers must not
 * auto-apply it.
 */
final class McpDenyExplanation {

  /**
   * Constructs an explanation.
   *
   * @param string $ruleId
   *   Stable rule machine name.
   * @param string $ruleName
   *   Short human name of the rule.
   * @param bool $widenAppropriate
   *   Whether an operator may consider widening. Never means "do it now".
   * @param string $nextStep
   *   Exact next human step.
   * @param string $summary
   *   One-line widening verdict.
   */
  public function __construct(
    public readonly string $ruleId,
    public readonly string $ruleName,
    public readonly bool $widenAppropriate,
    public readonly string $nextStep,
    public readonly string $summary,
  ) {}

  /**
   * Formats the suffix appended to a deny reason.
   */
  public function format(): string {
    $widen = $this->widenAppropriate
      ? 'Widening may be appropriate after a human review; it is never automatic.'
      : 'Widening is not appropriate; this deny must stay.';
    return sprintf(
      '[rule:%s %s] %s %s Next: %s',
      $this->ruleId,
      $this->ruleName,
      $this->summary,
      $widen,
      $this->nextStep,
    );
  }

}
