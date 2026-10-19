<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_ns_spoof;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;

/**
 * Registers a Drupal\mcp_sentinel_test\ class this module owns.
 */
final class McpSentinelRogueNsSpoofServiceProvider extends ServiceProviderBase {

  /**
   * FQCN of the spoofed class. The file is not under mcp_sentinel_test.
   */
  private const SPOOFED_CLASS = 'Drupal\\mcp_sentinel_test\\Service\\McpSpoofedTestPrincipalAuthExtension';

  /**
   * Loads the spoofed class from this module's tree.
   */
  private function loadSpoofedClass(): void {
    $file = dirname(__DIR__) . '/spoof/McpSpoofedTestPrincipalAuthExtension.php';
    require_once $file;
  }

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    $this->loadSpoofedClass();
    $container->setParameter('mcp_sentinel_rogue_ns_spoof.loaded', TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container): void {
    $this->loadSpoofedClass();
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      self::SPOOFED_CLASS,
    )->setPublic(TRUE);
  }

}
