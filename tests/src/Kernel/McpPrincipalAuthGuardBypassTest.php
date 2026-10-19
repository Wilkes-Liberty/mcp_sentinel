<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Spoof\SpoofedPrincipalAuthExtension;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder as SymfonyContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Request;

/**
 * Alias, later-pass, decorate, and rewire attacks stay denied.
 *
 * Each attack is applied during container compile. A stamped,
 * unproxied PATCH must stay claimless. Removing the guard
 * (process no-op or trustedAuthExtension identity) admits
 * rogue-subject; those mutants are shown red then restored.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpPrincipalAuthGuardBypassTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * Bypass applied in register() for the current test method.
   */
  private static string $bypass = '';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_test',
    'mcp_sentinel_rogue_auth',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    self::$bypass = match ($this->name()) {
      'testAliasOnNamespacedIdIsDenied' => 'alias',
      'testLaterBeforeRemovingPassIsDenied' => 'before_removing',
      'testLaterRemovePassIsDenied' => 'remove',
      'testLaterAfterRemovingPassIsDenied' => 'after_removing',
      'testDecorateWithTestModuleOnIsDenied' => 'decorate',
      'testArgumentRewireIsDenied' => 'rewire',
      'testSpoofedTestNamespaceClassIsDenied' => 'spoof',
      'testNullModuleHandlerRewireIsDenied' => 'null_handler',
      default => '',
    };
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    parent::register($container);
    match (self::$bypass) {
      'alias' => $this->registerAlias($container),
      'before_removing' => $this->registerLaterPass(
        $container,
        PassConfig::TYPE_BEFORE_REMOVING,
        -1000,
      ),
      'remove' => $this->registerLaterPass(
        $container,
        PassConfig::TYPE_REMOVE,
        0,
      ),
      'after_removing' => $this->registerLaterPass(
        $container,
        PassConfig::TYPE_AFTER_REMOVING,
        0,
      ),
      'decorate' => $this->registerDecorator($container),
      'rewire' => $this->registerRewire($container),
      'spoof' => $this->registerSpoof($container),
      'null_handler' => $this->registerNullHandler($container),
      default => NULL,
    };
  }

  /**
   * An alias onto a rogue class does not admit a fallback PATCH.
   */
  public function testAliasOnNamespacedIdIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * A later TYPE_BEFORE_REMOVING re-add does not admit.
   */
  public function testLaterBeforeRemovingPassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * A later TYPE_REMOVE re-add does not admit.
   */
  public function testLaterRemovePassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * A later TYPE_AFTER_REMOVING re-add does not admit.
   */
  public function testLaterAfterRemovingPassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * A decorator of the namespaced id does not admit.
   */
  public function testDecorateWithTestModuleOnIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * Rewiring factory and subscriber arguments does not admit.
   */
  public function testArgumentRewireIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * A spoofed Drupal\mcp_sentinel_test\ class is not honoured.
   */
  public function testSpoofedTestNamespaceClassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
  }

  /**
   * Rewiring module_handler to NULL still denies and writes refused.
   */
  public function testNullModuleHandlerRewireIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertRefusedAuditRow();
  }

  /**
   * Stamped, unproxied PATCH stays claimless and cannot take mcp_write.
   */
  private function assertStampedUnproxiedPatchDenied(): void {
    $request = Request::create('/jsonapi/node/page', 'PATCH');
    $request->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    $stack->push($request);

    $ctx = $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest($request);
    $this->assertSame('', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    $this->assertNotSame('rogue-subject', $ctx->subject());

    $this->expectException(McpPrincipalContextDeniedException::class);
    $this->container->get('mcp_sentinel.principal_context_dispatcher')
      ->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
  }

  /**
   * Alias the namespaced id onto the rogue class.
   */
  private function registerAlias(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_bypass.rogue',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $container->setAlias(
      'mcp_sentinel_test.principal_auth_extension',
      'mcp_sentinel_bypass.rogue',
    )->setPublic(TRUE);
  }

  /**
   * Re-add or replace the namespaced hook after the guard pass.
   */
  private function registerLaterPass(
    ContainerBuilder $container,
    string $type,
    int $priority,
  ): void {
    $container->addCompilerPass(
      new class implements CompilerPassInterface {

        /**
         * {@inheritdoc}
         */
        public function process(SymfonyContainerBuilder $container): void {
          $id = 'mcp_sentinel_test.principal_auth_extension';
          if ($container->hasDefinition($id)) {
            $container->getDefinition($id)
              ->setClass(McpRoguePrincipalAuthExtension::class);
          }
          else {
            $container->register($id, McpRoguePrincipalAuthExtension::class)
              ->setPublic(TRUE);
          }
          if ($container->hasDefinition('mcp_sentinel.principal_context_factory')) {
            $container->getDefinition('mcp_sentinel.principal_context_factory')
              ->setArgument(2, new Reference($id));
          }
          if ($container->hasDefinition('mcp_sentinel.principal_context_subscriber')) {
            $container->getDefinition('mcp_sentinel.principal_context_subscriber')
              ->setArgument(2, new Reference($id));
          }
        }

      },
      $type,
      $priority,
    );
  }

  /**
   * Decorate the namespaced hook with the rogue class.
   */
  private function registerDecorator(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpTestPrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $container->addCompilerPass(
      new class implements CompilerPassInterface {

        /**
         * {@inheritdoc}
         */
        public function process(SymfonyContainerBuilder $container): void {
          $id = 'mcp_sentinel_test.principal_auth_extension';
          if (!$container->hasDefinition($id)) {
            $container->register($id, McpTestPrincipalAuthExtension::class)
              ->setPublic(TRUE);
          }
          $container->setDefinition(
            $id . '.inner',
            $container->getDefinition($id),
          );
          $container->register($id, McpRoguePrincipalAuthExtension::class)
            ->setPublic(TRUE);
        }

      },
      PassConfig::TYPE_BEFORE_OPTIMIZATION,
      0,
    );
  }

  /**
   * Point factory and subscriber at a rogue service id.
   */
  private function registerRewire(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_bypass.rogue',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $rogue = new Reference('mcp_sentinel_bypass.rogue');
    $container->getDefinition('mcp_sentinel.principal_context_factory')
      ->setArgument(2, $rogue);
    $container->getDefinition('mcp_sentinel.principal_context_subscriber')
      ->setArgument(2, $rogue);
  }

  /**
   * Register a class under Drupal\mcp_sentinel_test\ from this test file.
   *
   * Runs at priority 0 so the guard at -1000 still sees the spoof
   * after mcp_sentinel_rogue_auth's YAML (higher priority runs first).
   */
  private function registerSpoof(ContainerBuilder $container): void {
    $container->addCompilerPass(
      new class implements CompilerPassInterface {

        /**
         * {@inheritdoc}
         */
        public function process(SymfonyContainerBuilder $container): void {
          $container->register(
            McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
            SpoofedPrincipalAuthExtension::class,
          )->setPublic(TRUE);
        }

      },
      PassConfig::TYPE_BEFORE_OPTIMIZATION,
      0,
    );
  }

  /**
   * Point factory and subscriber at a rogue id and drop the handler.
   */
  private function registerNullHandler(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_bypass.rogue',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $rogue = new Reference('mcp_sentinel_bypass.rogue');
    $container->getDefinition('mcp_sentinel.principal_context_factory')
      ->setArgument(2, $rogue)
      ->setArgument(4, NULL);
    $container->getDefinition('mcp_sentinel.principal_context_subscriber')
      ->setArgument(2, $rogue)
      ->setArgument(3, NULL);
  }

  /**
   * Latest principal_auth_extension_rejected row is refused.
   */
  private function assertRefusedAuditRow(): void {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpPrincipalContextFactory::AUDIT_OPERATION)
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $metadata = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $this->assertSame('refused', $metadata['reason'] ?? '');
  }

}

namespace Drupal\mcp_sentinel_test\Spoof;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class-string spoof: namespace matches, file is not the test module.
 */
final class SpoofedPrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

  /**
   * {@inheritdoc}
   */
  public function fallbackClaims(?Request $request): array {
    return [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'rogue-subject',
      'azp' => 'rogue-client',
      'tenant' => 'tenant-rogue',
      'scope' => 'mcp_read mcp_write',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function deferClaimlessSeal(Request $request): bool {
    return TRUE;
  }

}
