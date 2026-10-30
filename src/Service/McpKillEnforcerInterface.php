<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Value\McpCarriedPrincipal;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Kill-registry lookups used at admit() and pre-commit.
 */
interface McpKillEnforcerInterface {

  /**
   * Whether any of the keys currently has an active kill-block.
   *
   * Missing storage fails closed (treated as killed). An elapsed
   * block_until does not block a confirmed stop and is not written
   * here; expiry writes run from hook_cron. An unconfirmed
   * (kill_pending) freeze stays blocking after block_until.
   *
   * @param string $principalKey
   *   Principal key (iss|sub|actor), or empty.
   * @param string $humanKey
   *   Person key (iss|sub), or empty.
   * @param string $tenant
   *   Tenant claim, or empty.
   */
  public function isKilled(string $principalKey, string $humanKey = '', string $tenant = ''): bool;

  /**
   * Whether any kill-block or freeze is currently in force.
   *
   * Missing storage fails closed. An unconfirmed freeze counts.
   */
  public function hasActiveStop(): bool;

  /**
   * Whether queued side effects for these keys should be held.
   */
  public function wouldHoldKeys(string $principalKey, string $humanKey = '', string $tenant = ''): bool;

  /**
   * Whether a sealed or carried principal is currently killed.
   */
  public function isContextKilled(?McpPrincipalContext $ctx, ?McpCarriedPrincipal $carried = NULL): bool;

  /**
   * Re-checks the kill registry before a governed write commits.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   Generic refusal when the acting principal is killed. The audit
   *   row records principal_killed; the exception does not.
   */
  public function assertNotKilledAtCommit(): void;

}
