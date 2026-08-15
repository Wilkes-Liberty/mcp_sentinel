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
 *
 * Budgets are finite by default (#3616540): an unlimited (0) profile value is
 * clamped to the configured default request budget by McpReadBudgetResolver
 * unless the explicit non-production override is active.
 */
final class McpRateLimiter {

  /**
   * Constructs a McpRateLimiter instance.
   *
   * @param \Drupal\Core\Flood\FloodInterface $flood
   *   The core flood service.
   * @param \Drupal\mcp_sentinel\Service\McpReadBudgetResolver $budgets
   *   The finite-by-default budget resolver.
   */
  public function __construct(
    private readonly FloodInterface $flood,
    private readonly McpReadBudgetResolver $budgets,
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
    [$req, $win] = $this->budgets->effectiveRateLimit($profile);
    if ($req <= 0 || $win <= 0) {
      return TRUE;
    }
    // The uid is passed as the flood identifier explicitly: the default
    // identifier is the client IP, which would split one principal's budget
    // across as many buckets as it has addresses — IP rotation must never
    // multiply a quota (#3616540).
    return $this->flood->isAllowed(
      $this->key($profile->id(), $uid, $toolId),
      $req,
      $win,
      (string) $uid,
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
    [$req, $win] = $this->budgets->effectiveRateLimit($profile);
    if ($req <= 0 || $win <= 0) {
      return;
    }
    $this->flood->register($this->key($profile->id(), $uid, $toolId), $win, (string) $uid);
  }

  /**
   * Returns TRUE when the principal is within the collection page budget.
   *
   * Pagination cannot amplify a bounded per-request cap into an unbounded
   * export: collection reads consume a windowed per-principal budget
   * (#3616540). The budget values come from the resolver's finite defaults;
   * [0, 0] (the explicit override) disables the check.
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param int $uid
   *   Authenticated user ID (server-resolved, never agent-supplied).
   *
   * @return bool
   *   TRUE if another collection page is allowed, FALSE when over budget.
   */
  public function checkPageBudget(McpPolicyProfileInterface $profile, int $uid): bool {
    [$pages, $window] = $this->budgets->pageBudget();
    if ($pages <= 0 || $window <= 0) {
      return TRUE;
    }
    return $this->flood->isAllowed($this->pageKey($profile->id(), $uid), $pages, $window, (string) $uid);
  }

  /**
   * Registers one collection page. Call after a successful checkPageBudget().
   *
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   * @param int $uid
   *   Authenticated user ID (server-resolved, never agent-supplied).
   */
  public function registerPageBudget(McpPolicyProfileInterface $profile, int $uid): void {
    [$pages, $window] = $this->budgets->pageBudget();
    if ($pages <= 0 || $window <= 0) {
      return;
    }
    $this->flood->register($this->pageKey($profile->id(), $uid), $window, (string) $uid);
  }

  /**
   * Builds the page-budget flood key from server-resolved values only.
   *
   * @param string $profileId
   *   The profile machine ID.
   * @param int $uid
   *   The authenticated user ID.
   *
   * @return string
   *   The flood identifier string.
   */
  private function pageKey(string $profileId, int $uid): string {
    return "mcp_sentinel.pages.{$profileId}.{$uid}";
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
