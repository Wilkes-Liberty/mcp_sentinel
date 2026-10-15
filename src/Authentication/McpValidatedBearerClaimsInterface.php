<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Authentication;

use Symfony\Component\HttpFoundation\Request;

/**
 * Reads claims from a bearer the resource server has already accepted.
 */
interface McpValidatedBearerClaimsInterface {

  /**
   * Claims from a bearer that passed resource-server validation.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request carrying the Authorization header.
   *
   * @return array<string, mixed>|null
   *   The verified payload, or NULL when the bearer is missing or rejected.
   *   A rejected bearer is not parsed.
   */
  public function validatedClaims(Request $request): ?array;

}
