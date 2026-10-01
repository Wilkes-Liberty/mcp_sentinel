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
  case Unauthenticated = 'unauthenticated';

  /**
   * Whether this reason describes caller authorization, not system readiness.
   */
  public function isAuthorizationFailure(): bool {
    return in_array($this, [
      self::RequestConsumerNotDesignated,
      self::RequiredScopeMissing,
      self::Unauthenticated,
    ], TRUE);
  }

  /**
   * Operator-facing sentence for the failing gate. Never includes secrets.
   */
  public function operatorMessage(): string {
    return match ($this) {
      self::ModuleDisabled => 'MCP API access is off.',
      self::AuditDisabled => 'Audit logging is off, so the source-governance contract is not ready.',
      self::AuditWiringMissing => 'The audit-chain module is not available.',
      self::ServerModuleMissing => 'The MCP Sentinel Server module is not enabled.',
      self::ToolBridgeMissing => 'The MCP Server Tool Bridge module is not enabled.',
      self::OauthProviderMissing => 'The MCP Server OAuth provider is not enabled.',
      self::DesignatedConsumerMissing => 'No designated agent client is configured, or the configured client_id does not resolve to a Consumer.',
      self::DesignatedConsumerDisabled => 'The designated agent Consumer is disabled.',
      self::ConsumerAccountMissing => 'The designated Consumer has no owner account.',
      self::ConsumerAccountBlocked => 'The designated Consumer owner account is blocked.',
      self::AgentScopesMissing => 'No agent OAuth scopes are configured.',
      self::DevelopmentFallbackEnabled => 'The local-dev role fallback is on, so production readiness stays false.',
      self::ActiveProfileMissing => 'No enabled policy profile applies to the designated agent account.',
      self::ToolRegistrationMissing => 'A required Sentinel tool is not registered with mcp_server.',
      self::ToolRegistrationDisabled => 'A required Sentinel tool registration is disabled.',
      self::ToolAuthenticationNotRequired => 'A required Sentinel tool is registered without required OAuth.',
      self::ToolScopeMissing => 'A required Sentinel tool is missing its exact derived OAuth scope.',
      self::RequestConsumerNotDesignated => 'This request is not from a designated agent client.',
      self::RequiredScopeMissing => 'The token is missing the exact required OAuth scope.',
      self::Unauthenticated => 'The caller is not authenticated.',
    };
  }

  /**
   * Exact next operator step. Never auto-widens policy.
   */
  public function nextStep(): string {
    return match ($this) {
      self::ModuleDisabled => 'Turn on Enable MCP API access in MCP Sentinel settings.',
      self::AuditDisabled => 'Turn on Enable audit logging in MCP Sentinel settings.',
      self::AuditWiringMissing => 'Enable the audit_chain module and rebuild caches.',
      self::ServerModuleMissing => 'Enable mcp_sentinel_server and run drush mcp-sentinel:setup.',
      self::ToolBridgeMissing => 'Enable mcp_server_tool_bridge and run drush mcp-sentinel:setup.',
      self::OauthProviderMissing => 'Enable mcp_server_oauth so tools can require OAuth.',
      self::DesignatedConsumerMissing => 'Add a Consumer and enter its client_id under OAuth agent channel, or use Add agent client.',
      self::DesignatedConsumerDisabled => 'Re-enable the designated Consumer; do not mint tokens for a disabled client.',
      self::ConsumerAccountMissing => 'Set the Consumer owner to a dedicated agent account.',
      self::ConsumerAccountBlocked => 'Unblock the dedicated agent account, or point the Consumer at an active account.',
      self::AgentScopesMissing => 'Add mcp_read / mcp_write (and config scopes if needed) under OAuth agent channel.',
      self::DevelopmentFallbackEnabled => 'Turn off Govern by role without an OAuth token before treating this site as ready.',
      self::ActiveProfileMissing => 'Assign the agent role to an enabled policy profile. Do not widen a denylist to skip this.',
      self::ToolRegistrationMissing => 'Run drush mcp-sentinel:setup so required tools are registered.',
      self::ToolRegistrationDisabled => 'Re-enable the disabled mcp_tool_config entity, or rerun setup.',
      self::ToolAuthenticationNotRequired => 'Rerun setup without the development flag so OAuth is required.',
      self::ToolScopeMissing => 'Rerun setup so each tool carries its exact derived scope, and keep that scope in agent_scopes.',
      self::RequestConsumerNotDesignated => 'Mint or issue a token from a designated agent client. Do not widen allowlists to skip designation.',
      self::RequiredScopeMissing => 'Mint a token that includes the exact required scope. Do not drop the scope check.',
      self::Unauthenticated => 'Send a designated OAuth bearer or a short-lived sealed token. Do not grant anonymous access.',
    };
  }

}
