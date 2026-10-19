<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_test\Service;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test-module hook that returns keys the factory must drop.
 *
 * Used only to prove scopes, act, and client_id never survive
 * production admission. Owned by mcp_sentinel_test.
 */
final class McpDirtyClaimsPrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

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
      'scopes' => ['mcp_read', 'mcp_write'],
      'act' => ['sub' => 'rogue-actor'],
      'client_id' => 'rogue-client-id',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function deferClaimlessSeal(Request $request): bool {
    return FALSE;
  }

}
