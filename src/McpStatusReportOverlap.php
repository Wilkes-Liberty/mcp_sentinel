<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;

/**
 * Maps source-contract reasons onto overlapping Status report WARNING gaps.
 *
 * Drupal's Status report paints one severity per requirement key.
 * Empty agent scopes or a missing policy profile can produce both
 * mcp_sentinel_contract_not_ready (ERROR) and mcp_sentinel_not_governing
 * (WARNING). Those two keys are one operator-facing gap, so the
 * requirements hook keeps both severity labels on the ERROR row instead
 * of repeating it. Distinct gaps stay two rows.
 */
final class McpStatusReportOverlap {

  /**
   * Whether this contract reason already names the empty agent-channel gap.
   *
   * AgentScopesMissing is the first contract failure when both scopes and
   * clients are empty. The WARNING's "no request can be recognised as a
   * governed agent request" text describes that same empty channel.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason|null $reason
   *   The connector-facing contract reason, or NULL when the contract row
   *   was not recorded.
   *
   * @return bool
   *   TRUE when folding the channel WARNING into the contract ERROR.
   */
  public static function coversChannel(
    ?McpGovernanceReadinessReason $reason,
  ): bool {
    return $reason === McpGovernanceReadinessReason::AgentScopesMissing;
  }

  /**
   * Whether this contract reason already names the missing-profile gap.
   *
   * ActiveProfileMissing is the designated-account form of "no usable
   * policy profile". When no profile entity exists at all, the WARNING's
   * missing-profile item is the same gap.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason|null $reason
   *   The connector-facing contract reason, or NULL when the contract row
   *   was not recorded.
   *
   * @return bool
   *   TRUE when folding the profile WARNING into the contract ERROR.
   */
  public static function coversProfile(
    ?McpGovernanceReadinessReason $reason,
  ): bool {
    return $reason === McpGovernanceReadinessReason::ActiveProfileMissing;
  }

}
