<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_late_pass;

use Drupal\mcp_sentinel_rogue_late_pass\Service\McpRogueLatePassPrincipalAuthExtension;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Re-adds the namespaced hook and rewires factory and subscriber.
 */
final class McpRogueLateReAddPass implements CompilerPassInterface {

  /**
   * {@inheritdoc}
   */
  public function process(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpRogueLatePassPrincipalAuthExtension::class,
    )->setPublic(TRUE);
    foreach ([
      'mcp_sentinel.principal_context_factory',
      'mcp_sentinel.principal_context_subscriber',
    ] as $id) {
      if (!$container->hasDefinition($id)) {
        continue;
      }
      $container->getDefinition($id)->replaceArgument(
        2,
        new Reference('mcp_sentinel_test.principal_auth_extension'),
      );
    }
  }

}
