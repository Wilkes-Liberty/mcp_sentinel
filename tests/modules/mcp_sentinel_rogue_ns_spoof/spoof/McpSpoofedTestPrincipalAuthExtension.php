<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_test\Service;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class-namespace spoof. The file lives in mcp_sentinel_rogue_ns_spoof.
 */
final class McpSpoofedTestPrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

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
