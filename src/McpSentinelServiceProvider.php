<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Drupal\mcp_sentinel\Controller\McpDraftResource;
use Drupal\mcp_sentinel\Routing\McpDraftRoutes;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder as SymfonyContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Registers the optional JSON:API draft continuation surface.
 *
 * The principal-auth ownership guard runs at
 * TYPE_BEFORE_OPTIMIZATION / -1000 so aliases and later
 * optimization-time rewires are not resolved onto a foreign
 * target. Factory and subscriber constructors still check
 * the wired object.
 */
final class McpSentinelServiceProvider extends ServiceProviderBase implements CompilerPassInterface {

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    $container->addCompilerPass(
      $this,
      PassConfig::TYPE_BEFORE_OPTIMIZATION,
      -1000,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function process(SymfonyContainerBuilder $container): void {
    if (!$container instanceof ContainerBuilder) {
      throw new \LogicException(
        'McpSentinelServiceProvider::process() requires Drupal\\Core\\DependencyInjection\\ContainerBuilder.',
      );
    }
    $this->restrictPrincipalAuthExtension($container);
  }

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
   * The legacy mcp_sentinel.principal_auth_extension id is
   * removed when present. The namespaced id is kept only when
   * that test module is enabled and the class file lives
   * under that module's real path (info.yml basename), not
   * a Drupal\mcp_sentinel_test\ prefix.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container after every module alter(), before
   *   optimization.
   */
  private function restrictPrincipalAuthExtension(ContainerBuilder $container): void {
    $modules = $this->containerModules($container);
    $legacy = McpPrincipalContextFactory::AUTH_EXTENSION_LEGACY_ID;
    if ($container->hasDefinition($legacy) || $container->hasAlias($legacy)) {
      $this->recordCompileRejection(
        $container,
        $legacy,
        $this->principalAuthExtensionClass($container, $legacy),
        $modules,
      );
      if ($container->hasDefinition($legacy)) {
        $container->removeDefinition($legacy);
      }
      if ($container->hasAlias($legacy)) {
        $container->removeAlias($legacy);
      }
    }

    $id = McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID;
    if (!$container->hasDefinition($id) && !$container->hasAlias($id)) {
      return;
    }
    $testEnabled = isset($modules['mcp_sentinel_test']);
    $class = $this->principalAuthExtensionClass($container, $id);
    if ($testEnabled
      && McpPrincipalContextFactory::classOwnedByTestModule($class, $modules)) {
      return;
    }
    $this->recordCompileRejection($container, $id, $class, $modules);
    if ($container->hasDefinition($id)) {
      $container->removeDefinition($id);
    }
    if ($container->hasAlias($id)) {
      $container->removeAlias($id);
    }
  }

  /**
   * Appends one compile-time refusal to the compiled parameter.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param string $serviceId
   *   Offending service id.
   * @param string $class
   *   FQCN, or empty when unset.
   * @param array<string, mixed> $modules
   *   The container.modules parameter.
   */
  private function recordCompileRejection(
    ContainerBuilder $container,
    string $serviceId,
    string $class,
    array $modules,
  ): void {
    $rows = [];
    if ($container->hasParameter(McpPrincipalContextFactory::REJECTED_PARAMETER)) {
      $existing = $container->getParameter(
        McpPrincipalContextFactory::REJECTED_PARAMETER,
      );
      if (is_array($existing)) {
        $rows = $existing;
      }
    }
    $rows[] = [
      'service' => $serviceId,
      'provider' => $class !== ''
        ? McpPrincipalContextFactory::providerFromModuleMap($class, $modules)
        : '',
      'reason' => 'refused',
    ];
    $container->setParameter(
      McpPrincipalContextFactory::REJECTED_PARAMETER,
      $rows,
    );
  }

  /**
   * Installed-module map from the container, if present.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   *
   * @return array<string, mixed>
   *   The container.modules parameter, or an empty list.
   */
  private function containerModules(ContainerBuilder $container): array {
    $modules = $container->hasParameter('container.modules')
      ? $container->getParameter('container.modules')
      : [];
    return is_array($modules) ? $modules : [];
  }

  /**
   * Class name of the namespaced principal-auth hook, if any.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being altered.
   * @param string $id
   *   Service id or alias.
   *
   * @return string
   *   FQCN, or empty when unset.
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
