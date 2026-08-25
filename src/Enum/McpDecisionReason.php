<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Stable, non-secret reason codes for a typed decision.
 *
 * The backed value is the contract, following
 * McpGovernanceReadinessReason. Later slices add cases; they do not
 * rename these.
 */
enum McpDecisionReason: string {

  // Privilege escalation is always gated, independent of configuration.
  case AlwaysGated = 'always_gated';

  // The operation is in the configured gated set.
  case ApprovalRequired = 'approval_required';

  // The operation is not in the gated set and is not always-gated.
  case NotGated = 'not_gated';

  // No sealed manifest was stored on the request.
  case ManifestMissing = 'manifest_missing';

  // The stored document is not a valid seal for the current key.
  case ManifestInvalid = 'manifest_invalid';

  // The manifest expiry has passed.
  case ManifestExpired = 'manifest_expired';

  // The live target revision is not the revision that was sealed.
  case TargetStale = 'target_stale';

  // The idempotency key has already been consumed.
  case IdempotencyReplay = 'idempotency_replay';

  // The approver is the requester.
  case SelfApproval = 'self_approval';

  // The current account lacks the approve permission.
  case ApproverUnauthorized = 'approver_unauthorized';

  // The grantee is uid 1 or already holds an is_admin role.
  case SuperuserRefused = 'superuser_refused';

  // The signing key will not resolve, so a seal cannot be minted.
  case ManifestUnsealed = 'manifest_unsealed';

  // The execution receipt does not match the sealed target or outcome.
  case PostconditionDiscrepancy = 'postcondition_discrepancy';

}
