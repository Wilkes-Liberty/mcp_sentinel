<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Shared principal-key formula for rate limits, budgets, and kill.
 *
 * Other code imports this service (or its static formatters) instead of
 * assembling iss/sub/actor itself. The frozen context exposes the same
 * strings as principalKey() and humanKey().
 *
 *   principal = iss|sub|actor
 *   human     = iss|sub
 *
 * actor is the immediate act.sub when a delegation chain exists,
 * otherwise azp (falling back to client id).
 */
final class McpPrincipalKey {

  /**
   * Constructs the current-request accessor.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory $factory
   *   Token-derived context factory.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
  ) {}

  /**
   * Shared principal key: iss|sub|actor.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext|null $ctx
   *   Frozen context, or NULL to use the current request.
   */
  public function principalKey(?McpPrincipalContext $ctx = NULL): string {
    return self::formatPrincipal($ctx ?? $this->factory->fromCurrentRequest());
  }

  /**
   * Human principal key: iss|sub (no actor).
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext|null $ctx
   *   Frozen context, or NULL to use the current request.
   */
  public function humanKey(?McpPrincipalContext $ctx = NULL): string {
    return self::formatHuman($ctx ?? $this->factory->fromCurrentRequest());
  }

  /**
   * Formats iss|sub|actor from a frozen context.
   *
   * The formula lives on the context so a handler that already has ctx
   * does not need this service. This method is the import for code
   * that prefers a named helper.
   */
  public static function formatPrincipal(McpPrincipalContext $ctx): string {
    return $ctx->principalKey();
  }

  /**
   * Formats iss|sub from a frozen context.
   */
  public static function formatHuman(McpPrincipalContext $ctx): string {
    return $ctx->humanKey();
  }

}
