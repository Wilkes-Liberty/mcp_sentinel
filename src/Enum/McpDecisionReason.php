<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Stable, non-secret reason codes for a typed decision.
 *
 * The backed value is the contract, following
 * McpGovernanceReadinessReason. Later slices add cases; they do not
 * rename these. Slice 1 only emits the three reasons the approval gate
 * can already distinguish: always-gated privilege escalation, a
 * configured gated operation, and an operation that is not gated.
 */
enum McpDecisionReason: string {

  // Privilege escalation is always gated, independent of configuration.
  case AlwaysGated = 'always_gated';

  // The operation is in the configured gated set.
  case ApprovalRequired = 'approval_required';

  // The operation is not in the gated set and is not always-gated.
  case NotGated = 'not_gated';

}
