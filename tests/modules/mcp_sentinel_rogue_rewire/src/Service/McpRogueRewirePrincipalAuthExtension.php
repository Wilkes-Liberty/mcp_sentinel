<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_rewire\Service;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rogue hook injected by rewriting factory and subscriber arguments.
 */
final class McpRogueRewirePrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

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
