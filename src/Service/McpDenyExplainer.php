<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\Value\McpDenyExplanation;

/**
 * Names the policy rule behind a deny and whether widening is appropriate.
 *
 * Fail-closed and secret-free. Never auto-widens an allowlist or denylist.
 */
final class McpDenyExplainer {

  /**
   * Entity types that must stay denied even when an allowlist is edited.
   */
  private const CREDENTIAL_TYPES = [
    'user',
    'oauth2_token',
    'key',
    'consumer',
    'encryption_profile',
  ];

  /**
   * Builds a structured explanation from a deny reason string.
   *
   * @param string $reason
   *   Access-result reason or tool failure text. Must not contain secrets.
   * @param string|null $profileId
   *   Active policy profile id when known.
   *
   * @return \Drupal\mcp_sentinel\Value\McpDenyExplanation
   *   The explanation.
   */
  public function explain(string $reason, ?string $profileId = NULL): McpDenyExplanation {
    $profileHint = $profileId !== NULL && $profileId !== ''
      ? ' Edit policy profile "' . $profileId . '".'
      : ' Edit the active MCP policy profile.';

    if (str_contains($reason, 'classification_egress_denied')) {
      return new McpDenyExplanation(
        'classification_egress_denied',
        'classification egress ceiling',
        FALSE,
        'Lower the content classification or raise the profile ceiling only if a human intends that egress. Classification only ever denies more.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'policy_bundle_denied')) {
      return new McpDenyExplanation(
        'policy_bundle_denied',
        'attested policy bundle floor',
        FALSE,
        'Local deny cannot be widened by an upstream allow. Roll back or replace the attested bundle as an operator.',
        'Stay denied.',
      );
    }

    foreach (McpGovernanceReadinessReason::cases() as $code) {
      if (str_contains($reason, $code->value)) {
        return new McpDenyExplanation(
          $code->value,
          'source-governance contract',
          FALSE,
          $code->nextStep(),
          'Stay denied until the named gate is fixed. Do not widen an allowlist as a substitute.',
        );
      }
    }

    if (preg_match("/Entity type '([^']+)' is denied by MCP Sentinel/", $reason, $matches)) {
      $type = $matches[1];
      $credential = in_array($type, self::CREDENTIAL_TYPES, TRUE);
      return new McpDenyExplanation(
        'entity_type_denied',
        'entity-type denylist',
        !$credential,
        $credential
          ? 'Keep "' . $type . '" on the denylist. Credential-bearing types must stay denied.'
          : 'A human may remove "' . $type . '" from denied_entity_types if that type is editorial.' . $profileHint,
        $credential ? 'Stay denied.' : 'Human review only.',
      );
    }
    if (preg_match("/Entity type '([^']+)' is not in the MCP Sentinel allowlist/", $reason, $matches)) {
      $type = $matches[1];
      $credential = in_array($type, self::CREDENTIAL_TYPES, TRUE);
      return new McpDenyExplanation(
        'entity_type_allowlist',
        'entity-type allowlist',
        !$credential,
        $credential
          ? 'Do not add "' . $type . '" to the allowlist. Credential-bearing types stay out of agent scope.'
          : 'A human may add "' . $type . '" to allowed_entity_types if that type is editorial.' . $profileHint,
        $credential ? 'Stay denied.' : 'Human review only.',
      );
    }
    if (str_contains($reason, 'is denied by MCP Sentinel') && str_contains($reason, 'Configuration')) {
      return new McpDenyExplanation(
        'config_prefix_denied',
        'denied_config_types prefix denylist',
        FALSE,
        'Prefix denylist always wins. Do not remove secret-bearing prefixes such as key., encrypt., simple_oauth., or consumer.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'Write operations are disabled')) {
      return new McpDenyExplanation(
        'allow_write',
        'write gate',
        TRUE,
        'A human may enable writes on the policy profile for an editorial type. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Read operations are disabled')) {
      return new McpDenyExplanation(
        'allow_read',
        'read gate',
        TRUE,
        'A human may enable reads on the policy profile. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Delete operations are disabled')) {
      return new McpDenyExplanation(
        'allow_delete',
        'delete gate',
        TRUE,
        'A human may enable delete on the policy profile. Destructive ops may still need approval. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'Source IP not permitted')) {
      return new McpDenyExplanation(
        'ip_allowlist',
        'IP allowlist',
        TRUE,
        'A human may add this operator network to allowed_ips. Do not empty the list in production to skip the gate.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'MCP access is disabled')) {
      return new McpDenyExplanation(
        'module_disabled',
        'master switch',
        FALSE,
        'Turn on Enable MCP API access in MCP Sentinel settings. Do not widen a profile to bypass the master switch.',
        'Stay denied.',
      );
    }
    if (str_contains($reason, 'Rate limit exceeded') || str_contains($reason, 'request budget exceeded')) {
      return new McpDenyExplanation(
        'rate_limit',
        'rate or read budget',
        TRUE,
        'Retry after the window, or a human may raise the profile budget. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'exceeds the MCP Sentinel cap')) {
      return new McpDenyExplanation(
        'response_size_cap',
        'response size cap',
        TRUE,
        'Narrow the query, or a human may raise the profile response_size_cap. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }
    if (str_contains($reason, 'denied by policy') || str_contains($reason, 'Denied by MCP Sentinel') || str_contains($reason, 'Not in MCP Sentinel allowlist')) {
      return new McpDenyExplanation(
        'policy_default',
        'policy profile',
        TRUE,
        'Inspect the active policy profile allow/deny lists and operation gates. Widening is never automatic.' . $profileHint,
        'Human review only.',
      );
    }

    return new McpDenyExplanation(
      'unspecified',
      'policy profile',
      FALSE,
      'Inspect the audit log and the active policy profile. Do not widen an allowlist without a named rule.',
      'Stay denied until the rule is identified.',
    );
  }

  /**
   * Appends the explanation to a deny reason without duplicating it.
   *
   * @param string $reason
   *   Original deny reason.
   * @param string|null $profileId
   *   Active policy profile id when known.
   *
   * @return string
   *   Reason plus a non-secret rule suffix.
   */
  public function annotate(string $reason, ?string $profileId = NULL): string {
    if (str_contains($reason, '[rule:')) {
      return $reason;
    }
    return $reason . ' ' . $this->explain($reason, $profileId)->format();
  }

}
