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
 * removes any other definition at TYPE_BEFORE_OPTIMIZATION / -1000.
 * Ownership is that module's real path (info.yml basename), not a
 * class-namespace prefix and not a provider name, and is checked
 * against container.modules (the same map the compiler pass uses),
 * not @module_handler. The factory and subscriber fail closed on
 * the wired object. The subscriber re-checks before
 * deferClaimlessSeal(). A refused wired object, a compile-time
 * removal, and stripped claims each write an audit_chain row
 * (refused, or claims_stripped). Compile-time refusals are
 * flushed once per compiled parameter hash (state-keyed; once
 * per rebuild, not every request). A later compiler pass with
 * installed PHP can delete or forge container.modules or the
 * principal_auth_extension_rejected parameter. Production owns
 * admission: the factory calls fallbackClaims() only after the
 * fallback stamp and permitted() (which refuses a proxied hop),
 * and keeps iss/sub/azp/tenant only. The subscriber evaluates
 * the claimless predicate before consulting deferClaimlessSeal().
 * Absent that module the factory and subscriber receive NULL
 * and stay fail-closed.
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
