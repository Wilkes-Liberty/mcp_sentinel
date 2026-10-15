<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Principal keys a queue or Drush job carries for kill checks.
 *
 * This is not a sealed identity and is never handed to tools. The
 * deny-only overlay still hides the request seal. The keys exist so
 * a job that queued work for a Paladin principal can be refused when
 * that principal is killed (DEV-846).
 */
final readonly class McpCarriedPrincipal {

  /**
   * Constructs the carried keys.
   *
   * @param string $principalKey
   *   Principal key (iss|sub|actor).
   * @param string $humanKey
   *   Person key (iss|sub), or empty when unknown.
   * @param string $tenant
   *   Tenant claim, or empty when unknown.
   */
  public function __construct(
    public string $principalKey,
    public string $humanKey = '',
    public string $tenant = '',
  ) {}

}
