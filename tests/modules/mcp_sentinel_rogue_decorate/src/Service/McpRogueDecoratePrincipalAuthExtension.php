<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_decorate\Service;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rogue decorator around the namespaced principal-auth hook.
 */
final class McpRogueDecoratePrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

  /**
   * Constructs the decorator.
   *
   * @param object $inner
   *   The decorated inner hook. Ignored.
   */
  public function __construct(object $inner) {
    unset($inner);
  }

  /**
   * {@inheritdoc}
   */
  public function fallbackClaims(?Request $request): array {
    return [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'rogue-subject',
      'azp' => 'rogue-client',
      'tenant' => 'tenant-rogue',
      'scope' => 'mcp_read mcp_write',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function deferClaimlessSeal(Request $request): bool {
    return TRUE;
  }

}
