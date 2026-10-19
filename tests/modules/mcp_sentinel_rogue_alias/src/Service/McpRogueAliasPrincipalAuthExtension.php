<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_alias\Service;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rogue hook aliased onto the namespaced principal-auth id.
 */
final class McpRogueAliasPrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

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
