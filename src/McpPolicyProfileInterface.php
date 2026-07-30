<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\Core\Config\Entity\ConfigEntityInterface;

/**
 * Defines an MCP Sentinel policy profile.
 *
 * A profile is the per-agent governance posture: which operations are allowed,
 * which entity types are reachable, and which fields are redacted. Profiles
 * bind to user roles; the resolver picks the most specific match, falling back
 * to the 'default' profile.
 */
interface McpPolicyProfileInterface extends ConfigEntityInterface {

  /**
   * Role IDs this profile applies to (empty for the default/fallback profile).
   *
   * @return string[]
   *   The role IDs.
   */
  public function getRoles(): array;

  /**
   * Resolution weight; higher wins when several profiles match.
   */
  public function getWeight(): int;

  /**
   * Whether read operations are permitted under this profile.
   */
  public function allowsRead(): bool;

  /**
   * Whether write (create/update) operations are permitted under this profile.
   */
  public function allowsWrite(): bool;

  /**
   * Whether delete operations are permitted under this profile.
   */
  public function allowsDelete(): bool;

  /**
   * Whether GraphQL mutations are permitted under this profile.
   */
  public function allowsGraphqlMutations(): bool;

  /**
   * Allowed entity type IDs (empty = all allowed).
   *
   * @return string[]
   *   The allowed entity type IDs.
   */
  public function getAllowedEntityTypes(): array;

  /**
   * Denied entity type IDs.
   *
   * @return string[]
   *   The denied entity type IDs.
   */
  public function getDeniedEntityTypes(): array;

  /**
   * Field machine names redacted from MCP responses.
   *
   * @return string[]
   *   The redacted field machine names.
   */
  public function getRedactedFields(): array;

  /**
   * Maximum requests per rate-limit window (0 = unlimited).
   */
  public function getRateLimitRequests(): int;

  /**
   * Rate-limit window duration in seconds.
   */
  public function getRateLimitWindow(): int;

  /**
   * Maximum result items returned per tool/API call (0 = unlimited).
   */
  public function getResultCountCap(): int;

  /**
   * Maximum response size in bytes (0 = unlimited).
   */
  public function getResponseSizeCap(): int;

  /**
   * Allowed client IP addresses and CIDR ranges (empty = all IPs allowed).
   *
   * An empty list means no IP restriction is applied. Each entry is either a
   * single IP address (IPv4 or IPv6) or a CIDR block (e.g. 203.0.113.0/24 or
   * 2001:db8::/32). Matching is performed by Symfony IpUtils, which handles
   * both address families and CIDR notation correctly.
   *
   * IMPORTANT: IP allowlisting is only as trustworthy as the IP the site
   * resolves. When the site runs behind a reverse proxy, Drupal's trusted-proxy
   * settings ($settings['reverse_proxy'] and reverse_proxy_addresses in
   * settings.php) MUST be configured so that getClientIp() returns the real
   * client IP rather than the proxy's IP. Without those settings, all requests
   * appear to originate from the proxy and the allowlist will either lock out
   * legitimate agents or allow all of them.
   *
   * @return string[]
   *   IP addresses and/or CIDR ranges.
   */
  public function getAllowedIps(): array;

  /**
   * Whether configuration read operations are permitted under this profile.
   */
  public function allowsConfigRead(): bool;

  /**
   * Whether configuration write operations are permitted under this profile.
   */
  public function allowsConfigWrite(): bool;

  /**
   * Config name prefixes denied for read and write (deny always wins).
   *
   * Each entry is matched as a prefix against the full config object name
   * (e.g. 'system.', 'field.field.'). A config name matching any entry is
   * denied regardless of the allow_config_* flags.
   *
   * @return string[]
   *   The denied config name prefixes.
   */
  public function getDeniedConfigTypes(): array;

  /**
   * Whether the agent is forbidden from publishing content.
   *
   * When TRUE (the safe default), moderated transitions to a published state
   * are denied and unmoderated publishable entities are saved unpublished.
   */
  public function deniesPublish(): bool;

  /**
   * Highest moderation state the agent may set (empty = unrestricted).
   *
   * @return string
   *   The ceiling moderation state ID, or '' for no ceiling.
   */
  public function getMaxModerationState(): string;

  /**
   * Whether the agent is forbidden from creating off-domain redirects.
   *
   * When TRUE (the safe default), a governed agent may not create or update a
   * redirect whose destination is an external URL pointing at a host outside
   * the allowlist. Internal, entity:, base:, and relative targets are always
   * permitted.
   */
  public function deniesExternalRedirects(): bool;

  /**
   * Hostnames a governed agent may target with an external redirect.
   *
   * Empty means the site's own host(s) — derived from the request host and the
   * trusted_host_patterns setting — are the implicit allowlist.
   *
   * @return string[]
   *   The allowed redirect hostnames.
   */
  public function getAllowedRedirectHosts(): array;

  /**
   * Per-entity-type destructive overrides.
   *
   * A map of entity_type ID => rule. Each rule may carry an 'allow_delete',
   * 'allow_write' and/or 'allow_publish' boolean that overrides the
   * corresponding global flag for that entity type only. Empty means every type
   * follows the global flags.
   *
   * @return array<string, array{allow_delete?: bool, allow_write?: bool, allow_publish?: bool}>
   *   The per-entity-type rule map.
   */
  public function getEntityRules(): array;

  /**
   * Whether deleting an entity of the given type is permitted by this profile.
   *
   * Resolves the per-type override first and falls back to the global
   * allow_delete flag (entity_rules[type]['allow_delete'] ?? allowsDelete()).
   * This is the Sentinel gate only; the Drupal role permission still applies as
   * an independent second gate.
   *
   * @param string $entity_type
   *   The entity type ID being deleted.
   */
  public function allowsDeleteForEntityType(string $entity_type): bool;

  /**
   * Whether writing an entity of the given type is permitted by this profile.
   *
   * Resolves the per-type override first and falls back to the global
   * allow_write flag (entity_rules[type]['allow_write'] ?? allowsWrite()).
   *
   * @param string $entity_type
   *   The entity type ID being created or updated.
   */
  public function allowsWriteForEntityType(string $entity_type): bool;

  /**
   * Whether publishing an entity of the given type is denied by this profile.
   *
   * Resolves the per-type allow_publish override first and falls back to the
   * global deny_publish flag: entity_rules[type]['allow_publish'] present means
   * publishing is (dis)allowed for that type regardless of the global flag;
   * absent means the global deniesPublish() decides. The override works in
   * both directions, so an operator can relax one type (a redirect's `enabled`
   * flag is routing metadata whose real risk axis, the target, is constrained
   * by deny_external_redirects) or gate one sensitive type while keeping
   * publishing open globally. This keeps posture decisions in site config —
   * visible in config export and audit — instead of module code.
   *
   * @param string $entity_type
   *   The entity type ID being published.
   */
  public function deniesPublishForEntityType(string $entity_type): bool;

  /**
   * Permissions a role governed by this profile must not hold.
   *
   * These are escape hatches: each one lets its holder act outside the MCP
   * channel, where no policy profile, redaction or audit applies. A governed
   * role holding one does not weaken the profile, it makes the profile's
   * guarantees untrue — so this is asserted rather than assumed.
   *
   * @return string[]
   *   Permission machine names.
   *
   * @see \Drupal\mcp_sentinel\Service\McpRoleAssertions
   */
  public function getForbiddenRolePermissions(): array;

  /**
   * Deliberate grants that suppress a forbidden-permission violation.
   *
   * Entries are `role_id:permission`. An acknowledgement records an exception
   * in exported configuration, where a reviewer sees it, instead of the
   * alternative — deleting the rule that raised it, which loses the fact that
   * a decision was ever made.
   *
   * @return string[]
   *   `role_id:permission` strings.
   */
  public function getAcknowledgedRolePermissions(): array;

  /**
   * Whether this profile permits raw SQL through the governed Drush command.
   *
   * FALSE by default and on every profile that predates the knob. Raw SQL runs
   * underneath the entity API, so even the governed path
   * (mcp-sentinel:sql-query, checked by McpRawSqlGuard) is a narrower boundary
   * than an entity read: it constrains which tables and columns a statement
   * may touch, not what an expression over an allowed column can reconstruct.
   * Turning it on is therefore meant to be a deliberate, exported, reviewable
   * decision rather than something a profile inherits.
   *
   * @see \Drupal\mcp_sentinel\Service\McpRawSqlGuard
   */
  public function allowsRawSql(): bool;

}
