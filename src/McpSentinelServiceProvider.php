<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Drupal\mcp_sentinel\Controller\McpDraftResource;
use Drupal\mcp_sentinel\Routing\McpDraftRoutes;
use Symfony\Component\DependencyInjection\ChildDefinition;

/**
 * Registers the optional JSON:API draft continuation surface.
 */
final class McpSentinelServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container) {
    if ($container->hasDefinition('jsonapi.entity_resource')) {
      // Keep the JSON:API controller prefix so core's request subscribers and
      // normalizers recognise this as a JSON:API request.
      $definition = new ChildDefinition('jsonapi.entity_resource');
      $definition->setClass(McpDraftResource::class)->setPublic(TRUE);
      $container->setDefinition('jsonapi.entity_resource.mcp_draft', $definition);
      $container->register('mcp_sentinel.draft_routes', McpDraftRoutes::class)
        ->addTag('event_subscriber');
    }
  }

}
