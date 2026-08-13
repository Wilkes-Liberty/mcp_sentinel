<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Stable, non-secret source-governance readiness reason codes.
 */
enum McpGovernanceReadinessReason: string {

  case ModuleDisabled = 'module_disabled';
  case AuditDisabled = 'audit_disabled';
  case AuditWiringMissing = 'audit_wiring_missing';
  case ServerModuleMissing = 'server_module_missing';
  case ToolBridgeMissing = 'tool_bridge_missing';
  case OauthProviderMissing = 'oauth_provider_missing';
  case DesignatedConsumerMissing = 'designated_consumer_missing';
  case DesignatedConsumerDisabled = 'designated_consumer_disabled';
  case ConsumerAccountMissing = 'consumer_account_missing';
  case ConsumerAccountBlocked = 'consumer_account_blocked';
  case AgentScopesMissing = 'agent_scopes_missing';
  case DevelopmentFallbackEnabled = 'development_fallback_enabled';
  case ActiveProfileMissing = 'active_profile_missing';
  case ToolRegistrationMissing = 'tool_registration_missing';
  case ToolRegistrationDisabled = 'tool_registration_disabled';
  case ToolAuthenticationNotRequired = 'tool_authentication_not_required';
  case ToolScopeMissing = 'tool_scope_missing';
  case RequestConsumerNotDesignated = 'request_consumer_not_designated';
  case RequiredScopeMissing = 'required_scope_missing';

  /**
   * Whether this reason describes caller authorization, not system readiness.
   */
  public function isAuthorizationFailure(): bool {
    return in_array($this, [
      self::RequestConsumerNotDesignated,
      self::RequiredScopeMissing,
    ], TRUE);
  }

}
