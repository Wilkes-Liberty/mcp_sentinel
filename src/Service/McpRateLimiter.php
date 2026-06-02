<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Flood\FloodInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Enforces per-profile request-rate limits using the core flood service.
 *
 * Flood keys anchor on the server-resolved uid + profile id only. Agent-
 * supplied headers are never used as flood identifiers to prevent key-cycling
 * bypass attacks.
 */
final class McpRateLimiter {

  /**
   * Constructs a McpRateLimiter instance.
   *
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The core flood service.
   */
  public function __construct(
    private readonly FloodInterface $flood,
  ) {}

  /**
   * Returns TRUE when the account is within the profile's rate limit.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param int $uid
   *   Authenticated user ID (server-resolved, never agent-supplied).
   * @param string|null $toolId
   *   Optional tool plugin ID for per-tool flood key isolation. Pass NULL for
   *   the profile-wide check. Reserved for per-tool ceilings in a future pass.
   *
   * @return bool
   *   TRUE if the request is allowed, FALSE if throttled.
   */
  public function check(
    McpPolicyProfileInterface $profile,
    int $uid,
    ?string $toolId,
  ): bool {
    $req = $profile->getRateLimitRequests();
    $win = $profile->getRateLimitWindow();
    if ($req <= 0 || $win <= 0) {
      return TRUE;
    }
    return $this->flood->isAllowed(
      $this->key($profile->id(), $uid, $toolId),
      $req,
      $win,
    );
  }

  /**
   * Registers one hit. Call immediately after a successful check().
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param int $uid
   *   Authenticated user ID (server-resolved, never agent-supplied).
   * @param string|null $toolId
   *   Optional tool plugin ID for per-tool flood key isolation.
   */
  public function register(
    McpPolicyProfileInterface $profile,
    int $uid,
    ?string $toolId,
  ): void {
    $req = $profile->getRateLimitRequests();
    $win = $profile->getRateLimitWindow();
    if ($req <= 0 || $win <= 0) {
      return;
    }
    $this->flood->register($this->key($profile->id(), $uid, $toolId), $win);
  }

  /**
   * Builds the flood key from server-resolved values only.
   *
   * @param string $profileId
   *   The profile machine ID.
   * @param int $uid
   *   The authenticated user ID.
   * @param string|null $toolId
   *   Optional tool plugin ID.
   *
   * @return string
   *   The flood identifier string.
   */
  private function key(string $profileId, int $uid, ?string $toolId): string {
    $base = "mcp_sentinel.profile.{$profileId}.{$uid}";
    return $toolId !== NULL ? "{$base}.{$toolId}" : $base;
  }

}
