<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_alias;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;

/**
 * Replaces the namespaced hook id with an alias to this module.
 */
final class McpSentinelRogueAliasServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container): void {
    if ($container->hasDefinition('mcp_sentinel_test.principal_auth_extension')) {
      $container->removeDefinition('mcp_sentinel_test.principal_auth_extension');
    }
    if ($container->hasAlias('mcp_sentinel_test.principal_auth_extension')) {
      $container->removeAlias('mcp_sentinel_test.principal_auth_extension');
    }
    $container->setAlias(
      'mcp_sentinel_test.principal_auth_extension',
      'mcp_sentinel_rogue_alias.extension',
    )->setPublic(TRUE);
  }

}
