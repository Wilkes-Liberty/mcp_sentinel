<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Drupal\mcp_sentinel\Controller\McpDraftResource;
use Drupal\mcp_sentinel\Routing\McpDraftRoutes;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionOwnership;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder as SymfonyContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Registers the optional JSON:API draft continuation surface.
 *
 * The principal-auth ownership guard runs at
 * TYPE_BEFORE_OPTIMIZATION priority -1000 so alias, decorate,
 * and register passes have already been applied, and again
 * at TYPE_AFTER_REMOVING at PHP_INT_MIN so a later pass
 * cannot re-add the hook. Runtime admission still
 * fail-closes on the object wired into the factory and
 * subscriber.
 */
final class McpSentinelServiceProvider extends ServiceProviderBase implements CompilerPassInterface {

  /**
   * Factory and subscriber argument that holds the optional hook.
   */
  private const EXTENSION_ARGUMENT = 2;

  /**
   * Service ids whose constructor receives the optional hook.
   */
  private const HOOK_CONSUMERS = [
    'mcp_sentinel.principal_context_factory',
    'mcp_sentinel.principal_context_subscriber',
  ];

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    $container->addCompilerPass(
      $this,
      PassConfig::TYPE_BEFORE_OPTIMIZATION,
      -1000,
    );
    $container->addCompilerPass(
      $this,
      PassConfig::TYPE_AFTER_REMOVING,
      \PHP_INT_MIN,
    );
    if (!$container->hasParameter(McpPrincipalAuthExtensionOwnership::REJECTED_PARAMETER)) {
      $container->setParameter(
        McpPrincipalAuthExtensionOwnership::REJECTED_PARAMETER,
        [],
      );
    }
  }

  /**
   * {@inheritdoc}
   */
  public function process(SymfonyContainerBuilder $container): void {
    // CI weaken: skip the production compiler pass so the five
    // bypass-path kernel tests fail on their assertions.
    if (!$container instanceof ContainerBuilder) {
      return;
    }
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
   * The legacy id is always removed. Aliases and decorations are
   * resolved to the final definition. The namespaced id and any
   * factory or subscriber argument are kept only when the defining
   * module is mcp_sentinel_test, proven from that module's real
   * path. A failed check records the service and provider for an
   * audit_chain row and leaves the request on the sealed path.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container after alias, decorate, and register passes.
   */
  private function restrictPrincipalAuthExtension(ContainerBuilder $container): void {
    $modules = $this->moduleList($container);
    $this->dropService(
      $container,
      McpPrincipalAuthExtensionOwnership::LEGACY_ID,
      $modules,
      TRUE,
    );
    $this->dropDecoratorsOf(
      $container,
      McpPrincipalAuthExtensionOwnership::LEGACY_ID,
      $modules,
    );
    $this->dropDecoratorsOf(
      $container,
      McpPrincipalAuthExtensionOwnership::SERVICE_ID,
      $modules,
    );
    $this->dropService(
      $container,
      McpPrincipalAuthExtensionOwnership::SERVICE_ID,
      $modules,
      FALSE,
    );
    $this->nullUnauthorizedArguments($container, $modules);
  }

  /**
   * Removes $id unless it resolves to an owned definition.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param string $id
   *   Service id or alias.
   * @param array<string, mixed> $modules
   *   container.modules.
   * @param bool $always
   *   TRUE to drop even an owned definition (legacy id).
   */
  private function dropService(
    ContainerBuilder $container,
    string $id,
    array $modules,
    bool $always,
  ): void {
    if (!$container->hasDefinition($id) && !$container->hasAlias($id)) {
      return;
    }
    $resolved = $this->resolveToDefinition($container, $id);
    $class = $resolved['class'];
    $owned = $class !== ''
      && McpPrincipalAuthExtensionOwnership::classIsOwned($class, $modules);
    if (!$always && $owned) {
      return;
    }
    $provider = $resolved['provider'];
    if ($provider === '' && $class !== '') {
      $provider = McpPrincipalAuthExtensionOwnership::providerOfClass(
        $class,
        $modules,
      );
    }
    $this->rememberRejection($container, $id, $provider);
    if ($container->hasDefinition($id)) {
      $container->removeDefinition($id);
    }
    if ($container->hasAlias($id)) {
      $container->removeAlias($id);
    }
    if ($resolved['target'] !== $id
      && $container->hasDefinition($resolved['target'])
      && !$owned) {
      $container->removeDefinition($resolved['target']);
    }
  }

  /**
   * Drops services that decorate $innerId without owning it.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param string $innerId
   *   Decorated service id.
   * @param array<string, mixed> $modules
   *   container.modules.
   */
  private function dropDecoratorsOf(
    ContainerBuilder $container,
    string $innerId,
    array $modules,
  ): void {
    foreach ($container->getDefinitions() as $id => $definition) {
      $decorated = $definition->getDecoratedService();
      if ($decorated === NULL || ($decorated[0] ?? '') !== $innerId) {
        continue;
      }
      $class = (string) $definition->getClass();
      if (McpPrincipalAuthExtensionOwnership::classIsOwned($class, $modules)) {
        continue;
      }
      $provider = McpPrincipalAuthExtensionOwnership::providerOfClass(
        $class,
        $modules,
      );
      $this->rememberRejection($container, $id, $provider);
      $container->removeDefinition($id);
    }
  }

  /**
   * Nulls factory and subscriber arguments that are not owned.
   *
   * Catches a rewired constructor argument that no longer uses
   * the namespaced id.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param array<string, mixed> $modules
   *   container.modules.
   */
  private function nullUnauthorizedArguments(
    ContainerBuilder $container,
    array $modules,
  ): void {
    foreach (self::HOOK_CONSUMERS as $consumer) {
      if (!$container->hasDefinition($consumer)) {
        continue;
      }
      $definition = $container->getDefinition($consumer);
      $arguments = $definition->getArguments();
      if (!isset($arguments[self::EXTENSION_ARGUMENT])) {
        continue;
      }
      $argument = $arguments[self::EXTENSION_ARGUMENT];
      if (!$argument instanceof Reference) {
        continue;
      }
      $target = (string) $argument;
      if ($target === '') {
        continue;
      }
      $resolved = $this->resolveToDefinition($container, $target);
      if ($resolved['class'] !== ''
        && McpPrincipalAuthExtensionOwnership::classIsOwned(
          $resolved['class'],
          $modules,
        )) {
        continue;
      }
      $provider = $resolved['provider'];
      if ($provider === '' && $resolved['class'] !== '') {
        $provider = McpPrincipalAuthExtensionOwnership::providerOfClass(
          $resolved['class'],
          $modules,
        );
      }
      $this->rememberRejection($container, $target, $provider);
      $definition->replaceArgument(self::EXTENSION_ARGUMENT, NULL);
    }
  }

  /**
   * Follows aliases to the final definition class and provider.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param string $id
   *   Service id or alias.
   *
   * @return array{target: string, class: string, provider: string}
   *   Resolved target, class, and _provider tag when present.
   */
  private function resolveToDefinition(
    ContainerBuilder $container,
    string $id,
  ): array {
    $seen = [];
    $current = $id;
    while ($container->hasAlias($current)) {
      if (isset($seen[$current])) {
        return ['target' => $current, 'class' => '', 'provider' => ''];
      }
      $seen[$current] = TRUE;
      $current = (string) $container->getAlias($current);
    }
    if (!$container->hasDefinition($current)) {
      return ['target' => $current, 'class' => '', 'provider' => ''];
    }
    $definition = $container->getDefinition($current);
    return [
      'target' => $current,
      'class' => $this->definitionClass($definition),
      'provider' => $this->definitionProvider($definition),
    ];
  }

  /**
   * Class of a definition, following decoration to the outer class.
   *
   * After DecoratorServicePass the public id is already the
   * decorator. Before that pass, getClass() is this definition's
   * own class.
   *
   * @param \Symfony\Component\DependencyInjection\Definition $definition
   *   The resolved definition.
   *
   * @return string
   *   FQCN, or empty when unset.
   */
  private function definitionClass(Definition $definition): string {
    return (string) $definition->getClass();
  }

  /**
   * Provider tag written when YAML loaded the definition.
   *
   * @param \Symfony\Component\DependencyInjection\Definition $definition
   *   The resolved definition.
   *
   * @return string
   *   Module machine name, or empty.
   */
  private function definitionProvider(Definition $definition): string {
    $tags = $definition->getTags();
    $provider = $tags['_provider'][0]['provider'] ?? '';
    return is_string($provider) ? $provider : '';
  }

  /**
   * Records a compile-time rejection for a later audit_chain row.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param string $serviceId
   *   Offending service id.
   * @param string $provider
   *   Defining module.
   */
  private function rememberRejection(
    ContainerBuilder $container,
    string $serviceId,
    string $provider,
  ): void {
    $rejected = $container->hasParameter(McpPrincipalAuthExtensionOwnership::REJECTED_PARAMETER)
      ? $container->getParameter(McpPrincipalAuthExtensionOwnership::REJECTED_PARAMETER)
      : [];
    if (!is_array($rejected)) {
      $rejected = [];
    }
    $rejected[] = [
      'service' => $serviceId,
      'provider' => $provider,
    ];
    $container->setParameter(
      McpPrincipalAuthExtensionOwnership::REJECTED_PARAMETER,
      $rejected,
    );
  }

  /**
   * container.modules, or an empty list.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   *
   * @return array<string, mixed>
   *   Enabled extensions.
   */
  private function moduleList(ContainerBuilder $container): array {
    if (!$container->hasParameter('container.modules')) {
      return [];
    }
    $modules = $container->getParameter('container.modules');
    return is_array($modules) ? $modules : [];
  }

}
