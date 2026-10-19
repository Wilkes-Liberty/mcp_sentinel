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
 * mcp_sentinel_test.principal_auth_extension. Ownership is that
 * module's real path or provider, not a class-namespace prefix.
 * McpSentinelServiceProvider drops any other definition at
 * TYPE_BEFORE_OPTIMIZATION priority -1000, after alias, decorate,
 * and register passes, and again at TYPE_AFTER_REMOVING
 * PHP_INT_MIN. The factory and subscriber also fail closed
 * on the wired object unless the test gate is set. Production owns
 * admission: fallbackClaims() runs only after the fallback stamp,
 * an unproxied hop, and permitted(), and keeps iss/sub/azp/tenant
 * only. The subscriber evaluates the claimless predicate before
 * consulting deferClaimlessSeal(). A failed check ignores the hook
 * and writes an audit_chain governance row naming the service and
 * its provider (refused, or claims_stripped when extra keys are
 * dropped).
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
   *
   * @return bool
   *   TRUE to leave the request unsealed.
   */
  public function deferClaimlessSeal(Request $request): bool;

}
