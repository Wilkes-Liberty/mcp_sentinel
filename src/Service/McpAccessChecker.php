<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\IpUtils;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Enforces MCP Sentinel access control on entity operations.
 *
 * Applies the global master switch (mcp_sentinel.settings:enabled) and then the
 * resolved policy profile's gates and entity allow/deny lists. Works alongside
 * Drupal's core access system — both must allow an operation for it to proceed.
 *
 * IP allowlist enforcement uses Symfony's trusted-proxy-aware getClientIp() to
 * read the real client IP. See getAllowedIps() on McpPolicyProfileInterface for
 * the reverse-proxy configuration requirement.
 */
final class McpAccessChecker {

  /**
   * Constructs an McpAccessChecker.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack, used to read the trusted client IP.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly RequestStack $requestStack,
  ) {}

  /**
   * Checks whether an MCP operation on an entity is permitted under a profile.
   *
   * IP allowlist enforcement: if the profile has a non-empty allowed_ips list,
   * the request's client IP (obtained via Symfony's trusted-proxy-aware
   * getClientIp()) must match one of the configured IPs or CIDRs. An empty
   * allowed_ips list = no IP restriction. IPv4 and IPv6 single addresses and
   * CIDR blocks are all supported via Symfony IpUtils.
   *
   * NOTE — reverse-proxy requirement: getClientIp() only honors
   * X-Forwarded-For when the connecting proxy is in Drupal's trusted-proxy
   * list (reverse_proxy + reverse_proxy_addresses in settings.php). If those
   * settings are absent, getClientIp() returns the proxy's IP. Operators
   * MUST configure trusted proxies; see README for details.
   *
   * Cache safety: when the profile has a non-empty allowed_ips list, EVERY
   * AccessResult returned by this method is marked uncacheable (max-age 0).
   * Client IP is not a Drupal cache context, so a cached "allowed" result
   * would be re-served to a later request from the same account/roles but a
   * different, disallowed IP — bypassing the gate. Callers must not add their
   * own cache max-age when a profile carries IP restrictions.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being accessed.
   * @param string $operation
   *   The operation (e.g. 'view', 'update', 'create', 'delete').
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   Forbidden if the operation is disallowed; neutral otherwise.
   */
  public function checkEntityAccess(
    EntityInterface $entity,
    string $operation,
    McpPolicyProfileInterface $profile,
  ): AccessResult {
    $entityType = $entity->getEntityTypeId();
    $tags = [
      'config:mcp_sentinel.settings',
      'config:mcp_sentinel.mcp_policy_profile.' . $profile->id(),
    ];

    // When the profile carries an IP restriction, every result returned by
    // this method must be uncacheable: client IP is not a Drupal cache context,
    // so a cached "allowed" result could be re-served to a later request from
    // the same account but a different, disallowed IP.
    $ipRestricted = $profile->getAllowedIps() !== [];

    if (!$this->configFactory->get('mcp_sentinel.settings')->get('enabled')) {
      $result = AccessResult::forbidden('MCP access is disabled.')->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    // IP allowlist: deny before any operation gate if the client IP is not
    // in the profile's allowlist. Empty list = all IPs permitted.
    if ($ipRestricted && !$this->isClientIpAllowed($profile)) {
      return AccessResult::forbidden(
        'Source IP not permitted by MCP Sentinel policy.'
      )->addCacheTags($tags)->setCacheMaxAge(0);
    }

    $typeResult = $this->checkEntityTypePolicy($entityType, $profile, $tags);
    if ($typeResult !== NULL) {
      return $ipRestricted ? $typeResult->setCacheMaxAge(0) : $typeResult;
    }

    if ($operation === 'view' && !$profile->allowsRead()) {
      $result = AccessResult::forbidden(
        'Read operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }
    if (in_array($operation, ['update', 'create'], TRUE) && !$profile->allowsWrite()) {
      $result = AccessResult::forbidden(
        'Write operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }
    if ($operation === 'delete' && !$profile->allowsDelete()) {
      $result = AccessResult::forbidden(
        'Delete operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    $result = AccessResult::neutral()->addCacheTags($tags);
    return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
  }

  /**
   * Checks whether creating an entity of a given type is permitted.
   *
   * This is the create-access counterpart to checkEntityAccess(). It exists
   * because hook_entity_access() does NOT fire for entity CREATE — Drupal's
   * entity create-access path (EntityAccessControlHandler::createAccess() →
   * hook_entity_create_access) is a separate seam. JSON:API POST (new entity)
   * routes through that seam, so without this method a governed agent could
   * POST a new entity and bypass the write gate, the allowed/denied
   * entity-type policy, and the IP allowlist.
   *
   * It enforces exactly the CREATE-relevant governance, matching the semantics
   * of checkEntityAccess() for the same gates (no new divergence):
   *  - the master switch (mcp_sentinel.settings:enabled),
   *  - the IP allowlist (isClientIpAllowed()),
   *  - the allowed/denied entity-type policy (shared with checkEntityAccess()
   *    via checkEntityTypePolicy()),
   *  - the write gate (allowsWrite()), since create is a write.
   *
   * The same cacheability rules apply: when the profile carries a non-empty
   * allowed_ips list every result is marked uncacheable (max-age 0), because
   * client IP is not a Drupal cache context. Callers (the hook) add the
   * 'user.roles' and 'oauth2_scopes' cache contexts.
   *
   * @param string $entityTypeId
   *   The entity type ID being created (from $context['entity_type_id']).
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   Forbidden if the create is disallowed; neutral otherwise.
   */
  public function checkCreateAccess(
    string $entityTypeId,
    McpPolicyProfileInterface $profile,
  ): AccessResult {
    $tags = [
      'config:mcp_sentinel.settings',
      'config:mcp_sentinel.mcp_policy_profile.' . $profile->id(),
    ];
    $ipRestricted = $profile->getAllowedIps() !== [];

    if (!$this->configFactory->get('mcp_sentinel.settings')->get('enabled')) {
      $result = AccessResult::forbidden('MCP access is disabled.')->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    // IP allowlist: deny before any operation gate if the client IP is not
    // in the profile's allowlist. Empty list = all IPs permitted.
    if ($ipRestricted && !$this->isClientIpAllowed($profile)) {
      return AccessResult::forbidden(
        'Source IP not permitted by MCP Sentinel policy.'
      )->addCacheTags($tags)->setCacheMaxAge(0);
    }

    // Shared allowed/denied entity-type policy (same logic as the existing
    // entity-access path).
    $typeResult = $this->checkEntityTypePolicy($entityTypeId, $profile, $tags);
    if ($typeResult !== NULL) {
      return $ipRestricted ? $typeResult->setCacheMaxAge(0) : $typeResult;
    }

    // Create is a write, so the write gate must permit it.
    if (!$profile->allowsWrite()) {
      $result = AccessResult::forbidden(
        'Write operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    $result = AccessResult::neutral()->addCacheTags($tags);
    return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
  }

  /**
   * Returns a forbidden result if the entity type violates the profile policy.
   *
   * Shared by checkEntityAccess() and checkCreateAccess() so the allowed/denied
   * entity-type policy has exactly ONE implementation. Returns NULL when the
   * entity type satisfies the policy (so the caller may continue), or a
   * forbidden AccessResult (with the supplied cache tags, but WITHOUT any
   * max-age handling — the caller applies the IP-restriction max-age 0) when
   * the type is denied or not in a non-empty allowlist.
   *
   * @param string $entityTypeId
   *   The entity type ID to check.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param string[] $tags
   *   Cache tags to attach to any forbidden result.
   *
   * @return \Drupal\Core\Access\AccessResult|null
   *   A forbidden result when the type is disallowed, NULL when permitted.
   */
  private function checkEntityTypePolicy(
    string $entityTypeId,
    McpPolicyProfileInterface $profile,
    array $tags,
  ): ?AccessResult {
    if (in_array($entityTypeId, $profile->getDeniedEntityTypes(), TRUE)) {
      return AccessResult::forbidden(
        "Entity type '{$entityTypeId}' is denied by MCP Sentinel."
      )->addCacheTags($tags);
    }
    $allowed = $profile->getAllowedEntityTypes();
    if ($allowed && !in_array($entityTypeId, $allowed, TRUE)) {
      return AccessResult::forbidden(
        "Entity type '{$entityTypeId}' is not in the MCP Sentinel allowlist."
      )->addCacheTags($tags);
    }
    return NULL;
  }

  /**
   * Returns TRUE if the current client IP is permitted by the IP allowlist.
   *
   * An empty allowlist (allowed_ips = []) means no restriction — all IPs are
   * permitted. When the list is non-empty, the client IP obtained via Symfony's
   * trusted-proxy-aware Request::getClientIp() must match at least one entry.
   *
   * This is the single canonical IP-check implementation. All code paths that
   * need IP-gate enforcement (checkEntityAccess(), governed tool plugins, the
   * context controller) must call this method rather than re-implementing the
   * check inline.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return bool
   *   TRUE when the client IP is permitted (or no IP restriction is set),
   *   FALSE when the client IP is absent or not in the allowlist.
   */
  public function isClientIpAllowed(McpPolicyProfileInterface $profile): bool {
    $allowedIps = $profile->getAllowedIps();
    if ($allowedIps === []) {
      return TRUE;
    }
    $request = $this->requestStack->getCurrentRequest();
    $clientIp = $request !== NULL ? (string) $request->getClientIp() : '';
    return $clientIp !== '' && IpUtils::checkIp($clientIp, $allowedIps);
  }

  /**
   * Returns JSON:API filter access rules for an entity type under a profile.
   *
   * @param string $entityTypeId
   *   The entity type ID to check.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return array
   *   An array of JSONAPI_FILTER_AMONG_* constant keys to AccessResult values,
   *   or an empty array when the entity type is unrestricted.
   */
  public function getJsonApiFilterAccess(
    string $entityTypeId,
    McpPolicyProfileInterface $profile,
  ): array {
    // Every governed filter-access result must carry the same cacheability
    // metadata as the other governed access hooks (mcp_sentinel_entity_access,
    // _create_access, _field_access). Without the 'user.roles' and
    // 'oauth2_scopes' cache contexts, JSON:API's filter-access cache can serve
    // a governed deny-result to a non-governed account (or vice-versa) sharing
    // the cache bin — a cache-bleed governance bypass. When the profile carries
    // an IP restriction the result is additionally uncacheable (client IP is
    // not a Drupal cache context), consistent with checkEntityAccess().
    $contexts = ['user.roles', 'oauth2_scopes'];
    $tags = [
      'config:mcp_sentinel.settings',
      'config:mcp_sentinel.mcp_policy_profile.' . $profile->id(),
    ];
    $ipRestricted = $profile->getAllowedIps() !== [];

    $decorate = function (AccessResult $result) use ($contexts, $tags, $ipRestricted): AccessResult {
      $result->addCacheContexts($contexts)->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    };

    if (in_array($entityTypeId, $profile->getDeniedEntityTypes(), TRUE)) {
      return [JSONAPI_FILTER_AMONG_ALL => $decorate(AccessResult::forbidden('Denied by MCP Sentinel.'))];
    }
    $allowed = $profile->getAllowedEntityTypes();
    if ($allowed && !in_array($entityTypeId, $allowed, TRUE)) {
      return [JSONAPI_FILTER_AMONG_ALL => $decorate(AccessResult::forbidden('Not in MCP Sentinel allowlist.'))];
    }
    return [];
  }

}
