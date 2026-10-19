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
    $this->restrictPrincipalAuthExtension($container);
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
        new Reference('entity_field.manager'),
        new Reference('mcp_sentinel.translation_draft_reporter'),
      ]);
      $container->setDefinition('jsonapi.entity_resource.mcp_draft', $definition);
      $container->register('mcp_sentinel.draft_routes', McpDraftRoutes::class)
        ->addTag('event_subscriber');
    }
  }

  /**
   * Drops a principal-auth hook that mcp_sentinel_test does not own.
   *
   * The legacy mcp_sentinel.principal_auth_extension id is always
   * removed. The namespaced id is kept only when that test module
   * is enabled and the class lives under Drupal\mcp_sentinel_test\.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being altered.
   */
  private function restrictPrincipalAuthExtension(ContainerBuilder $container): void {
    $legacy = 'mcp_sentinel.principal_auth_extension';
    if ($container->hasDefinition($legacy)) {
      $container->removeDefinition($legacy);
    }
    if ($container->hasAlias($legacy)) {
      $container->removeAlias($legacy);
    }

    $id = 'mcp_sentinel_test.principal_auth_extension';
    if (!$container->hasDefinition($id) && !$container->hasAlias($id)) {
      return;
    }
    $modules = $container->hasParameter('container.modules')
      ? $container->getParameter('container.modules')
      : [];
    $testEnabled = is_array($modules) && isset($modules['mcp_sentinel_test']);
    $class = $this->principalAuthExtensionClass($container, $id);
    if ($testEnabled && str_starts_with($class, 'Drupal\\mcp_sentinel_test\\')) {
      return;
    }
    if ($container->hasDefinition($id)) {
      $container->removeDefinition($id);
    }
    if ($container->hasAlias($id)) {
      $container->removeAlias($id);
    }
  }

  /**
   * Class name of the namespaced principal-auth hook, if any.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being altered.
   * @param string $id
   *   Service id or alias.
   */
  private function principalAuthExtensionClass(ContainerBuilder $container, string $id): string {
    if ($container->hasDefinition($id)) {
      return (string) $container->getDefinition($id)->getClass();
    }
    if (!$container->hasAlias($id)) {
      return '';
    }
    $target = (string) $container->getAlias($id);
    if (!$container->hasDefinition($target)) {
      return '';
    }
    return (string) $container->getDefinition($target)->getClass();
  }

}
