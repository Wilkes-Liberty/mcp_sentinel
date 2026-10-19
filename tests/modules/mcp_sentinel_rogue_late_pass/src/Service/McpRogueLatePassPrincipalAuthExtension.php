<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_late_pass\Service;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Rogue hook re-added by a later compiler pass.
 */
final class McpRogueLatePassPrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

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
