<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Drupal\mcp_sentinel\Controller\McpDraftResource;
use Drupal\mcp_sentinel\Routing\McpDraftRoutes;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Registers the optional JSON:API draft continuation surface.
 */
final class McpSentinelServiceProvider extends ServiceProviderBase {

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container): void {
    if ($container->hasDefinition('jsonapi.entity_resource')) {
      // Keep the JSON:API controller prefix so core's request subscribers and
      // normalizers recognize this as a JSON:API request.
      $definition = new ChildDefinition('jsonapi.entity_resource');
      $definition->setClass(McpDraftResource::class)->setPublic(TRUE);
      $definition->addMethodCall('setDraftServices', [
        new Reference('database'),
        new Reference('mcp_sentinel.policy_resolver'),
        new Reference('content_moderation.moderation_information', ContainerBuilder::NULL_ON_INVALID_REFERENCE),
        new Reference('language_manager'),
        new Reference('content_translation.manager', ContainerBuilder::NULL_ON_INVALID_REFERENCE),
      ]);
      $container->setDefinition('jsonapi.entity_resource.mcp_draft', $definition);
      $container->register('mcp_sentinel.draft_routes', McpDraftRoutes::class)
        ->addTag('event_subscriber');
    }
  }

}
