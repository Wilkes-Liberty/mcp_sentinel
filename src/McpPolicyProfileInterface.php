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

}
