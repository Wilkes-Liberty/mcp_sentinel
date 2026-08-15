<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\EntityInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\IpUtils;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
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
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface|null $entityTypeManager
   *   The entity type manager, used to recognize composite-child entity types
   *   for the governed creation grant (d.o #3616669). Nullable with a NULL
   *   default for the deploy window only: until the container rebuilds, the
   *   cached service definition still passes two arguments, and a required
   *   third would fatal every request in that window. Degradation is
   *   fail-closed — without the service the grant simply never applies.
   * @param \Drupal\mcp_sentinel\Service\McpClassificationResolver|null $classification
   *   The classification resolver enforcing per-surface egress ceilings
   *   (d.o #3616540 part 2). Nullable for the same deploy window; without it
   *   no ceiling is evaluated, which is exactly the pre-upgrade behavior.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly RequestStack $requestStack,
    private readonly ?EntityTypeManagerInterface $entityTypeManager = NULL,
    private readonly ?McpClassificationResolver $classification = NULL,
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
    if (in_array($operation, ['update', 'create'], TRUE) && !$profile->allowsWriteForEntityType($entityType)) {
      $result = AccessResult::forbidden(
        'Write operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }
    if ($operation === 'delete' && !$profile->allowsDeleteForEntityType($entityType)) {
      $result = AccessResult::forbidden(
        'Delete operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    // Classification egress ceiling (d.o #3616540 part 2), evaluated LAST:
    // every hard deny above wins first, so labels only ever deny more. Reads
    // include 'view label' — a label-only representation is still egress.
    $result = AccessResult::neutral()->addCacheTags($tags);
    if (in_array($operation, ['view', 'view label'], TRUE) && $this->classification !== NULL) {
      $result = $this->checkClassification($entity, $profile, $result);
    }
    return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
  }

  /**
   * Applies the profile's egress ceiling for the current surface to a read.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being read.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param \Drupal\Core\Access\AccessResult $neutral
   *   The neutral result to return (with cacheability) when nothing exceeds.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   The neutral result, or a forbidden result carrying the stable code
   *   classification_egress_denied. Either way, when the site labels anything
   *   above the floor the result varies by route and by the declared ceiling.
   */
  private function checkClassification(
    EntityInterface $entity,
    McpPolicyProfileInterface $profile,
    AccessResult $neutral,
  ): AccessResult {
    assert($this->classification !== NULL);
    if (!$this->classification->assignsAboveLowest()) {
      // Nothing is labelled above the floor: no ceiling can refuse anything,
      // and the decision does not depend on surface or declaration.
      return $neutral;
    }
    $surface = $this->classification->currentSurface();
    $ceiling = $this->classification->effectiveCeiling($profile, $surface);
    $label = $this->classification->labelForEntity($entity);
    if ($ceiling === NULL || !$this->classification->exceeds($label, $ceiling)) {
      return $neutral->addCacheContexts(McpClassificationResolver::CACHE_CONTEXTS);
    }
    $this->classification->evidence(
      $profile,
      $surface,
      $entity->getEntityTypeId(),
      $entity->bundle(),
      '',
      $label,
      $ceiling,
    );
    // The bare code is the reason on purpose: JSON:API repeats access reasons
    // to the client in meta.omitted, so label prose must not travel there.
    return AccessResult::forbidden(McpClassificationResolver::DENIAL_CODE)
      ->addCacheTags($neutral->getCacheTags())
      ->addCacheContexts(McpClassificationResolver::CACHE_CONTEXTS);
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
   *   Forbidden if the create is disallowed; allowed when every gate passes
   *   and the entity type is a composite child (d.o #3616669); neutral
   *   otherwise.
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

    // Create is a write, so the write gate must permit it (per-type override
    // falls back to the global allow_write flag).
    if (!$profile->allowsWriteForEntityType($entityTypeId)) {
      $result = AccessResult::forbidden(
        'Write operations are disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    // Composite-child grant (d.o #3616669). A composite child (a paragraph)
    // cannot be created over an API at all upstream: its access handler allows
    // creation only in HTML form context and stays neutral for API formats,
    // which collapses to 403 — so the connector's create-then-reference flow
    // is impossible even under a write-allowed profile. The governed channel
    // supplies the policy context standalone creation lacks, so once every
    // gate above has passed, Sentinel grants creation for entity types that
    // declare a revision parent (composites only — non-composite types keep
    // their neutral fall-through so core role permissions still decide them).
    // A standalone composite is inert until a host references it, and that
    // host save runs the full governance stack.
    $definition = $this->entityTypeManager?->getDefinition($entityTypeId, FALSE);
    if ($definition !== NULL && $definition->get('entity_revision_parent_type_field') !== NULL) {
      $result = AccessResult::allowed()->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    $result = AccessResult::neutral()->addCacheTags($tags);
    return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
  }

  /**
   * Checks whether an MCP configuration operation is permitted under a profile.
   *
   * The config-governance counterpart to checkEntityAccess(). Enforces the same
   * master switch and IP-allowlist gates, then the config-specific policy: the
   * denied_config_types prefix denylist (deny always wins), the config-read
   * gate for read/view operations, and the allow_config_write gate for
   * write/update operations.
   *
   * Cache safety mirrors checkEntityAccess(): when the profile carries a
   * non-empty allowed_ips list every result is uncacheable (max-age 0).
   *
   * @param string $configName
   *   The full configuration object name (e.g. 'system.site').
   * @param string $operation
   *   The operation: 'read'/'view' or 'write'/'update'.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile for the requesting account.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   Forbidden if the operation is disallowed; neutral otherwise.
   */
  public function checkConfigAccess(
    string $configName,
    string $operation,
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

    if ($ipRestricted && !$this->isClientIpAllowed($profile)) {
      return AccessResult::forbidden(
        'Source IP not permitted by MCP Sentinel policy.'
      )->addCacheTags($tags)->setCacheMaxAge(0);
    }

    $typeResult = $this->checkConfigTypePolicy($configName, $profile, $tags);
    if ($typeResult !== NULL) {
      return $ipRestricted ? $typeResult->setCacheMaxAge(0) : $typeResult;
    }

    if (in_array($operation, ['read', 'view'], TRUE) && !$profile->allowsConfigRead()) {
      $result = AccessResult::forbidden(
        'Configuration read is disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }
    if (in_array($operation, ['write', 'update'], TRUE) && !$profile->allowsConfigWrite()) {
      $result = AccessResult::forbidden(
        'Configuration write is disabled in MCP Sentinel.'
      )->addCacheTags($tags);
      return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
    }

    $result = AccessResult::neutral()->addCacheTags($tags);
    return $ipRestricted ? $result->setCacheMaxAge(0) : $result;
  }

  /**
   * Returns a forbidden result if the config name is on the profile denylist.
   *
   * The denylist entries are matched as prefixes against the full config name
   * (e.g. 'system.' denies 'system.site'). Deny always wins, independent of the
   * allow_config_* flags. Returns NULL when the config name is permitted.
   *
   * @param string $configName
   *   The full configuration object name.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param string[] $tags
   *   Cache tags to attach to any forbidden result.
   *
   * @return \Drupal\Core\Access\AccessResult|null
   *   A forbidden result when the config name is denied, NULL when permitted.
   */
  public function checkConfigTypePolicy(
    string $configName,
    McpPolicyProfileInterface $profile,
    array $tags,
  ): ?AccessResult {
    foreach ($profile->getDeniedConfigTypes() as $prefix) {
      if ($prefix !== '' && str_starts_with($configName, $prefix)) {
        return AccessResult::forbidden(
          "Configuration '{$configName}' is denied by MCP Sentinel."
        )->addCacheTags($tags);
      }
    }
    return NULL;
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

    // Classification (d.o #3616540 part 2): filter access is entity-type
    // granular, and a relationship-path filter is a value oracle on any
    // bundle or field of the type. So the whole type is judged by its most
    // sensitive row — deny more, never less — and filtering is refused
    // type-wide when that row exceeds the JSON:API ceiling.
    if ($this->classification !== NULL && $this->classification->assignsAboveLowest()) {
      $ceiling = $this->classification->effectiveCeiling($profile, McpGovernedSurface::JsonApi);
      $highest = $this->classification->highestLabelForEntityType($entityTypeId);
      if ($ceiling !== NULL && $this->classification->exceeds($highest, $ceiling)) {
        $this->classification->evidence($profile, McpGovernedSurface::JsonApi, $entityTypeId, '', '', $highest, $ceiling);
        return [
          JSONAPI_FILTER_AMONG_ALL => $decorate(AccessResult::forbidden(McpClassificationResolver::DENIAL_CODE))
            ->addCacheContexts(McpClassificationResolver::CACHE_CONTEXTS),
        ];
      }
    }
    return [];
  }

}
