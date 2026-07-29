<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Resolves whether a request is governed and which policy profile applies.
 *
 * Governance keys on the validated OAuth agent channel (consumer client_id or
 * agent scope on the request's access token). The Phase-1 role-based check is
 * retained only as a local-dev fallback, enabled by the governed_role_fallback
 * setting. Profile selection still uses the account's roles so per-admin
 * policy stays intact even on OAuth-authenticated requests (TokenAuthUser
 * returns the subject's roles via getRoles()).
 */
final class McpPolicyResolver {

  /**
   * Roles that must never govern (they would capture all/anonymous traffic).
   */
  private const FORBIDDEN_ROLES = ['anonymous', 'authenticated'];

  /**
   * Constructs a McpPolicyResolver.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager service.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   The OAuth context service used to detect the agent channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly AccountProxyInterface $currentUser,
    private readonly McpOauthContext $oauthContext,
  ) {}

  /**
   * Returns the full set of governed role IDs.
   *
   * Combines roles from mcp_sentinel.settings:governed_roles with roles
   * referenced by any enabled policy profile.
   *
   * @return string[]
   *   A deduplicated list of governed role IDs.
   */
  public function getGovernedRoles(): array {
    $roles = $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('governed_roles') ?? [];
    foreach ($this->loadProfiles() as $profile) {
      $roles = array_merge($roles, $profile->getRoles());
    }
    // Never let anonymous/authenticated govern — that would capture all traffic
    // regardless of how the config was set (UI or hand-edited YAML).
    $roles = array_diff($roles, self::FORBIDDEN_ROLES);
    return array_values(array_unique(array_filter($roles)));
  }

  /**
   * Determines whether the current request is a governed MCP agent request.
   *
   * Governed when the request is authenticated on the OAuth agent channel
   * (designated consumer client_id or an agent scope on the access token).
   * The role-based check is only honoured as a local-dev fallback when
   * governed_role_fallback is explicitly enabled in settings. This ensures
   * that an admin's cookie-session UI stays ungoverned while their
   * token-bearing agent traffic is fully governed and audited.
   *
   * @param \Drupal\Core\Session\AccountInterface|null $account
   *   The account to check for role fallback, or NULL to use the current user.
   *
   * @return bool
   *   TRUE if this request is on the governed agent channel, or if the
   *   role fallback is enabled and the account holds a governed role.
   */
  public function isGoverned(?AccountInterface $account = NULL): bool {
    if ($this->oauthContext->isAgentChannel()) {
      return TRUE;
    }
    $config = $this->configFactory->get('mcp_sentinel.settings');
    if (!$config->get('governed_role_fallback')) {
      return FALSE;
    }
    $account ??= $this->currentUser;
    return (bool) array_intersect($account->getRoles(), $this->getGovernedRoles());
  }

  /**
   * Returns the active policy profile for the given account.
   *
   * Returns the highest-weight enabled profile whose roles intersect the
   * account's roles, falling back to the 'default' profile. Returns NULL if
   * the account is not governed.
   *
   * @param \Drupal\Core\Session\AccountInterface|null $account
   *   The account to resolve for, or NULL to use the current user.
   *
   * @return \Drupal\mcp_sentinel\McpPolicyProfileInterface|null
   *   The resolved profile, or NULL if the account is not governed.
   */
  public function resolve(
    ?AccountInterface $account = NULL,
  ): ?McpPolicyProfileInterface {
    $account ??= $this->currentUser;
    if (!$this->isGoverned($account)) {
      return NULL;
    }

    return $this->resolveForRoles($account->getRoles());
  }

  /**
   * Returns the profile that governs an arbitrary set of role IDs.
   *
   * Split out of resolve() so callers that have no account and no request —
   * notably the governed raw-SQL Drush command, which runs on the CLI where
   * there is no OAuth channel to key on — resolve a profile through exactly
   * the same weighting and tie-breaking as an HTTP request would, instead of
   * reimplementing it and drifting.
   *
   * This deliberately does NOT consult isGoverned(): it answers "which profile
   * covers these roles", not "is this request governed". Callers that need the
   * latter must ask separately.
   *
   * @param string[] $roles
   *   Role IDs to match profiles against.
   *
   * @return \Drupal\mcp_sentinel\McpPolicyProfileInterface|null
   *   The highest-weight matching profile, the role-less default profile when
   *   nothing matches, or NULL when no profile exists at all.
   */
  public function resolveForRoles(array $roles): ?McpPolicyProfileInterface {
    $best = NULL;
    $default = NULL;
    foreach ($this->loadProfiles() as $profile) {
      $profileRoles = $profile->getRoles();
      if (!$profileRoles) {
        $default = $profile;
        continue;
      }
      // Highest weight wins; ties break deterministically on the profile ID so
      // resolution never depends on storage iteration order.
      if (array_intersect($profileRoles, $roles)) {
        if ($best === NULL
          || $profile->getWeight() > $best->getWeight()
          || ($profile->getWeight() === $best->getWeight() && $profile->id() < $best->id())) {
          $best = $profile;
        }
      }
    }
    return $best ?? $default;
  }

  /**
   * Loads all enabled policy profiles.
   *
   * @return \Drupal\mcp_sentinel\McpPolicyProfileInterface[]
   *   An array of enabled profile entities.
   */
  private function loadProfiles(): array {
    $profiles = $this->entityTypeManager
      ->getStorage('mcp_policy_profile')
      ->loadMultiple();
    $result = [];
    foreach ($profiles as $profile) {
      if ($profile instanceof McpPolicyProfileInterface && $profile->status()) {
        $result[] = $profile;
      }
    }
    return $result;
  }

}
