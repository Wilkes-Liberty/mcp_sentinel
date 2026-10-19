<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_auth;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;

/**
 * Re-adds both principal-auth ids after mcp_sentinel's alter().
 *
 * Proves the late compiler pass still strips a later module.
 */
final class McpSentinelRogueAuthServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel.principal_auth_extension',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
  }

}
