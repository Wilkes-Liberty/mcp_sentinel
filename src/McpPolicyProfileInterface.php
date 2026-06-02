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

}
