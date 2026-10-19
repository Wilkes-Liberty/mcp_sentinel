<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Symfony\Component\HttpFoundation\Request;

/**
 * Optional principal-builder hook. Production never implements this.
 *
 * @internal
 *
 * The mcp_sentinel_test module registers the only implementation, as
 * mcp_sentinel_test.principal_auth_extension. McpSentinelServiceProvider
 * drops any other definition. Production owns admission: the factory
 * calls fallbackClaims() only after the fallback stamp, an unproxied
 * hop, and permitted(), and keeps iss/sub/azp/tenant only. The
 * subscriber evaluates the claimless predicate before consulting
 * deferClaimlessSeal(). Absent that module the factory and subscriber
 * receive NULL and stay fail-closed.
 */
interface McpPrincipalAuthExtensionInterface {

  /**
   * Extra claims after readiness stamps role fallback.
   *
   * A real bearer is never replaced. Proxied requests stay empty.
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request readiness has already stamped, or NULL.
   *
   * @return array<string, string>
   *   iss, sub, and azp, plus tenant when present. Empty to leave
   *   the factory's validated claims unchanged.
   */
  public function fallbackClaims(?Request $request): array;

  /**
   * TRUE to skip sealing a claimless request (wait for fallback).
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The main request.
   */
  public function deferClaimlessSeal(Request $request): bool;

}
