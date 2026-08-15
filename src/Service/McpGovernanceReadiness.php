<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\Entity\ConfigEntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\mcp_sentinel\Value\McpGovernanceReadinessResult;
use Drupal\Core\Session\AccountInterface;
use Drupal\tool\Tool\ToolManager;
use Drupal\user\UserInterface;

/**
 * Evaluates the connector-facing source-governance readiness contract.
 *
 * This contract proves only that required local source-governance wiring is
 * present. It does not assert policy effectiveness, posture, audit-chain
 * verification, external evidence durability, or hosted readiness.
 */
final class McpGovernanceReadiness {

  /**
   * OAuth provider for MCP Tool configuration third-party settings.
   */
  private const OAUTH_PROVIDER = 'mcp_server_oauth';

  /**
   * Optional callback used to test compiled plugin presence.
   *
   * @var (\Closure(string): bool)|null
   */
  private readonly ?\Closure $toolExists;

  /**
   * Constructs the readiness service.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Configuration factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Entity type manager.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Module handler.
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Policy resolver.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   Request OAuth context.
   * @param \Drupal\audit_chain\AuditChainLoggerInterface|null $auditChain
   *   Audit-chain logger when the module is available.
   * @param \Drupal\tool\Tool\ToolManager|null $toolManager
   *   Tool plugin manager used to derive the production scope map.
   * @param array<string, string>|null $requiredToolScopes
   *   Optional required-tool map for isolated contract tests.
   * @param (\Closure(string): bool)|null $toolExists
   *   Optional compiled-plugin predicate for isolated contract tests.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpOauthContext $oauthContext,
    private readonly ?AuditChainLoggerInterface $auditChain,
    private readonly ?ToolManager $toolManager = NULL,
    private readonly ?array $requiredToolScopes = NULL,
    ?\Closure $toolExists = NULL,
  ) {
    $this->toolExists = $toolExists;
  }

  /**
   * Returns the current connector-facing source-governance contract status.
   */
  public function contractStatus(): McpGovernanceReadinessResult {
    $settings = $this->configFactory->get('mcp_sentinel.settings');
    if (!(bool) $settings->get('enabled')) {
      return $this->denied(McpGovernanceReadinessReason::ModuleDisabled);
    }
    if (!(bool) $settings->get('audit_enabled')) {
      return $this->denied(McpGovernanceReadinessReason::AuditDisabled);
    }
    if (!$this->moduleHandler->moduleExists('audit_chain') || $this->auditChain === NULL) {
      return $this->denied(McpGovernanceReadinessReason::AuditWiringMissing);
    }
    if (!$this->moduleHandler->moduleExists('mcp_sentinel_server')) {
      return $this->denied(McpGovernanceReadinessReason::ServerModuleMissing);
    }
    if (!$this->moduleHandler->moduleExists('mcp_server_tool_bridge')) {
      return $this->denied(McpGovernanceReadinessReason::ToolBridgeMissing);
    }
    if (!$this->moduleHandler->moduleExists(self::OAUTH_PROVIDER)) {
      return $this->denied(McpGovernanceReadinessReason::OauthProviderMissing);
    }
    if ((bool) $settings->get('governed_role_fallback')) {
      return $this->denied(McpGovernanceReadinessReason::DevelopmentFallbackEnabled);
    }

    $configuredScopes = $this->nonemptyStrings($settings->get('agent_scopes'));
    if ($configuredScopes === []) {
      return $this->denied(McpGovernanceReadinessReason::AgentScopesMissing);
    }

    $clientIds = $this->nonemptyStrings($settings->get('agent_oauth_clients'));
    if ($clientIds === []) {
      return $this->denied(McpGovernanceReadinessReason::DesignatedConsumerMissing);
    }

    $profile = NULL;
    foreach ($clientIds as $clientId) {
      $identity = $this->resolveDesignatedIdentity($clientId);
      if ($identity instanceof McpGovernanceReadinessResult) {
        return $identity;
      }
      $profile = $identity;
    }

    $toolFailure = $this->checkToolRegistrations($configuredScopes, $profile);
    return $toolFailure ?? McpGovernanceReadinessResult::ready($profile);
  }

  /**
   * Evaluates one incoming request against the same readiness contract.
   *
   * Ordinary JSON:API/GraphQL traffic remains neutral. Dedicated Tool/context
   * paths always require either a designated OAuth principal or the explicit
   * development role fallback.
   *
   * $requiredScope is one exact scope, or a list of acceptable scopes when
   * the HTTP seam cannot see the GraphQL operation type.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpGovernedSurface $surface
   *   The governed surface being evaluated.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The requesting account.
   * @param string|string[] $requiredScope
   *   Exact required OAuth scope, or any-of scopes for the GraphQL HTTP seam.
   *
   * @return \Drupal\mcp_sentinel\Value\McpGovernanceReadinessResult
   *   The readiness decision.
   */
  public function evaluate(
    McpGovernedSurface $surface,
    AccountInterface $account,
    string|array $requiredScope,
  ): McpGovernanceReadinessResult {
    $settings = $this->configFactory->get('mcp_sentinel.settings');
    $oauthRequest = $this->oauthContext->isOauthRequest();
    $designated = $this->oauthContext->isDesignatedAgentClient();
    $fallback = !$oauthRequest
      && (bool) $settings->get('governed_role_fallback')
      && (bool) array_intersect(
        $account->getRoles(),
        $this->policyResolver->getGovernedRoles(),
      );

    if (!$surface->isDedicated() && !$designated && !$fallback) {
      return McpGovernanceReadinessResult::notApplicable();
    }

    if ($fallback) {
      if (!(bool) $settings->get('enabled')) {
        return $this->denied(McpGovernanceReadinessReason::ModuleDisabled);
      }
      if (!(bool) $settings->get('audit_enabled')
        || !$this->moduleHandler->moduleExists('audit_chain')
        || $this->auditChain === NULL) {
        return $this->denied(McpGovernanceReadinessReason::AuditWiringMissing);
      }
      $profile = $this->policyResolver->resolveForRoles($account->getRoles());
      return $profile instanceof McpPolicyProfileInterface && $profile->status()
        ? McpGovernanceReadinessResult::ready($profile)
        : $this->denied(McpGovernanceReadinessReason::ActiveProfileMissing);
    }

    $contract = $this->contractStatus();
    if (!$contract->isReady()) {
      return $contract;
    }
    if (!$designated) {
      return $this->denied(McpGovernanceReadinessReason::RequestConsumerNotDesignated);
    }
    $requiredScopes = is_array($requiredScope) ? $requiredScope : [$requiredScope];
    $hasRequiredScope = FALSE;
    foreach ($requiredScopes as $scope) {
      if ($this->oauthContext->hasScope($scope)) {
        $hasRequiredScope = TRUE;
        break;
      }
    }
    if (!$hasRequiredScope) {
      return $this->denied(McpGovernanceReadinessReason::RequiredScopeMissing);
    }
    $profile = $this->policyResolver->resolveForRoles($account->getRoles());
    return $profile instanceof McpPolicyProfileInterface && $profile->status()
      ? McpGovernanceReadinessResult::ready($profile)
      : $this->denied(McpGovernanceReadinessReason::ActiveProfileMissing);
  }

  /**
   * Resolves one exact configured client to its applicable active profile.
   *
   * @return \Drupal\mcp_sentinel\McpPolicyProfileInterface|\Drupal\mcp_sentinel\Value\McpGovernanceReadinessResult
   *   The applicable profile or a fail-closed reason.
   */
  private function resolveDesignatedIdentity(
    string $clientId,
  ): McpPolicyProfileInterface|McpGovernanceReadinessResult {
    if (!$this->entityTypeManager->hasDefinition('consumer')) {
      return $this->denied(McpGovernanceReadinessReason::DesignatedConsumerMissing);
    }
    $found = $this->entityTypeManager
      ->getStorage('consumer')
      ->loadByProperties(['client_id' => $clientId]);
    $consumer = $found ? reset($found) : NULL;
    if (!$consumer instanceof ConsumerInterface || $consumer->getClientId() !== $clientId) {
      return $this->denied(McpGovernanceReadinessReason::DesignatedConsumerMissing);
    }
    if (!$consumer->isPublished()) {
      return $this->denied(McpGovernanceReadinessReason::DesignatedConsumerDisabled);
    }

    if (!$this->entityTypeManager->hasDefinition('user')) {
      return $this->denied(McpGovernanceReadinessReason::ConsumerAccountMissing);
    }
    $account = $this->entityTypeManager
      ->getStorage('user')
      ->load($consumer->getOwnerId());
    if (!$account instanceof UserInterface) {
      return $this->denied(McpGovernanceReadinessReason::ConsumerAccountMissing);
    }
    if (!$account->isActive()) {
      return $this->denied(McpGovernanceReadinessReason::ConsumerAccountBlocked);
    }

    $profile = $this->policyResolver->resolveForRoles($account->getRoles());
    if (!$profile instanceof McpPolicyProfileInterface || !$profile->status()) {
      return $this->denied(McpGovernanceReadinessReason::ActiveProfileMissing);
    }
    $profileRoles = $this->nonemptyStrings($profile->getRoles());
    if ($profileRoles === [] || !array_intersect($account->getRoles(), $profileRoles)) {
      // A role-less default or unrelated active profile is not proof that this
      // designated principal has an applicable production policy.
      return $this->denied(McpGovernanceReadinessReason::ActiveProfileMissing);
    }

    return $profile;
  }

  /**
   * Validates every compiled Sentinel tool registration.
   */
  private function checkToolRegistrations(
    array $configuredScopes,
    McpPolicyProfileInterface $profile,
  ): ?McpGovernanceReadinessResult {
    if (!$this->entityTypeManager->hasDefinition('mcp_tool_config')) {
      return $this->denied(McpGovernanceReadinessReason::ToolRegistrationMissing, $profile);
    }

    $expected = $this->requiredToolScopes;
    if ($expected === NULL) {
      if ($this->toolManager === NULL) {
        return $this->denied(McpGovernanceReadinessReason::ToolRegistrationMissing, $profile);
      }
      $expected = [];
      foreach (McpToolScopeResolver::REQUIRED_TOOLS as $toolId) {
        if (!$this->toolManager->hasDefinition($toolId)) {
          return $this->denied(McpGovernanceReadinessReason::ToolRegistrationMissing, $profile);
        }
        $expected[$toolId] = McpToolScopeResolver::resolveDefinition(
          $this->toolManager->getDefinition($toolId),
        );
      }
      foreach (McpToolScopeResolver::OPTIONAL_TOOLS as $toolId) {
        if ($this->toolManager->hasDefinition($toolId)) {
          $expected[$toolId] = McpToolScopeResolver::resolveDefinition(
            $this->toolManager->getDefinition($toolId),
          );
        }
      }
    }
    elseif ($this->compiledToolExists('mcp_sentinel_graphql_schema')) {
      $expected['mcp_sentinel_graphql_schema'] = 'mcp_read';
    }
    $registrations = $this->entityTypeManager
      ->getStorage('mcp_tool_config')
      ->loadMultiple();

    foreach ($expected as $toolId => $requiredScope) {
      $tool = $registrations[$toolId] ?? NULL;
      if (!$tool instanceof ConfigEntityInterface) {
        return $this->denied(McpGovernanceReadinessReason::ToolRegistrationMissing, $profile);
      }
      if (!$tool->status()) {
        return $this->denied(McpGovernanceReadinessReason::ToolRegistrationDisabled, $profile);
      }
      if ($tool->getThirdPartySetting(self::OAUTH_PROVIDER, 'authentication_mode') !== 'required') {
        return $this->denied(McpGovernanceReadinessReason::ToolAuthenticationNotRequired, $profile);
      }
      $scopes = $this->nonemptyStrings(
        $tool->getThirdPartySetting(self::OAUTH_PROVIDER, 'scopes', []),
      );
      if ($scopes !== [$requiredScope] || !in_array($requiredScope, $configuredScopes, TRUE)) {
        return $this->denied(McpGovernanceReadinessReason::ToolScopeMissing, $profile);
      }
    }

    return NULL;
  }

  /**
   * Whether an optional compiled tool exists in this rebuilt container.
   */
  private function compiledToolExists(string $toolId): bool {
    if ($this->toolExists !== NULL) {
      return ($this->toolExists)($toolId);
    }
    return $this->toolManager?->hasDefinition($toolId) ?? FALSE;
  }

  /**
   * Filters arbitrary configuration input to unique nonempty strings.
   *
   * @return string[]
   *   Normalized values.
   */
  private function nonemptyStrings(mixed $values): array {
    if (!is_array($values)) {
      return [];
    }
    $strings = array_filter(
      $values,
      static fn (mixed $value): bool => is_string($value) && trim($value) !== '',
    );
    return array_values(array_unique($strings));
  }

  /**
   * Creates a denied contract result.
   */
  private function denied(
    McpGovernanceReadinessReason $reason,
    ?McpPolicyProfileInterface $profile = NULL,
  ): McpGovernanceReadinessResult {
    return McpGovernanceReadinessResult::denied($reason, $profile);
  }

}
