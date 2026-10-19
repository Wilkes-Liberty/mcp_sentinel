<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_rewire;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Points factory and subscriber at this module's hook.
 */
final class McpSentinelRogueRewireServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container): void {
    foreach ([
      'mcp_sentinel.principal_context_factory',
      'mcp_sentinel.principal_context_subscriber',
    ] as $id) {
      if (!$container->hasDefinition($id)) {
        continue;
      }
      $container->getDefinition($id)->replaceArgument(
        2,
        new Reference('mcp_sentinel_rogue_rewire.extension'),
      );
    }
  }

}
