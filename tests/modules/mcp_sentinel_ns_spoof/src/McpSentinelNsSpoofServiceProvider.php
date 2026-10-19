<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_ns_spoof;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;

/**
 * Makes the foreign-path spoof class loadable before the guard pass.
 */
final class McpSentinelNsSpoofServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    $file = dirname(__DIR__) . '/src/NsSpoofPrincipalAuthExtension.php';
    if (is_file($file)) {
      require_once $file;
    }
  }

}
