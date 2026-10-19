<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_late_pass;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;

/**
 * Registers late compiler passes that re-add the principal-auth hook.
 *
 * TYPE_BEFORE_REMOVING at -1000, TYPE_REMOVE, and TYPE_AFTER_REMOVING
 * all run after TYPE_BEFORE_OPTIMIZATION -1000.
 */
final class McpSentinelRogueLatePassServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    $container->addCompilerPass(
      new McpRogueLateReAddPass(),
      PassConfig::TYPE_BEFORE_REMOVING,
      -1000,
    );
    $container->addCompilerPass(
      new McpRogueLateReAddPass(),
      PassConfig::TYPE_REMOVE,
    );
    $container->addCompilerPass(
      new McpRogueLateReAddPass(),
      PassConfig::TYPE_AFTER_REMOVING,
      \PHP_INT_MIN,
    );
  }

}
