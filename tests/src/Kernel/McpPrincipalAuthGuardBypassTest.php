<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_rogue_auth\LyingTestModulePathHandler;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_rogue_auth\StubOwningTestModuleHandler;
use Drupal\mcp_sentinel_test\Service\McpTestExtraClaimsPrincipalAuthExtension;
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
 * unproxied PATCH must stay claimless. Compile-stripped
 * paths assert the hook is gone and a flushed row names
 * service, reason, and provider. Runtime-refuse paths
 * assert a row the compile flush cannot explain. Removing
 * the guard, container.modules ownership, or runtime
 * recordRejection() admits rogue-subject or drops that row.
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
    if (getenv('MCP_SENTINEL_REQUIRE_ZEND_ASSERTIONS') === '1') {
      $this->assertSame(
        '1',
        ini_get('zend.assertions'),
        'zend.assertions must be 1 in the bypass PHP process.',
      );
    }
    self::$bypass = match ($this->name()) {
      'testAliasOnNamespacedIdIsDenied' => 'alias',
      'testLaterBeforeRemovingPassIsDenied' => 'before_removing',
      'testLaterRemovePassIsDenied' => 'remove',
      'testLaterAfterRemovingPassIsDenied' => 'after_removing',
      'testDecorateWithTestModuleOnIsDenied' => 'decorate',
      'testArgumentRewireIsDenied' => 'rewire',
      'testSpoofedTestNamespaceClassIsDenied' => 'spoof',
      'testNullModuleHandlerRewireIsDenied' => 'null_handler',
      'testStubModuleHandlerRewireIsDenied' => 'stub_handler',
      'testStubModuleHandlerStillAdmitsOwnedExtension' => 'stub_owned',
      'testDecoratedModuleHandlerRewireIsDenied' => 'decorated_handler',
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
      'stub_handler' => $this->registerStubHandler($container),
      'stub_owned' => $this->registerStubOwnedHandler($container),
      'decorated_handler' => $this->registerDecoratedHandler($container),
      default => NULL,
    };
  }

  /**
   * An alias onto a rogue class does not admit a fallback PATCH.
   */
  public function testAliasOnNamespacedIdIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertNamespacedHookRemoved();
    $this->assertCompileFlushedRejection('mcp_sentinel_rogue_auth');
  }

  /**
   * A later TYPE_BEFORE_REMOVING re-add does not admit.
   */
  public function testLaterBeforeRemovingPassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertCompileParameterHas(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      'mcp_sentinel_rogue_auth',
    );
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
  }

  /**
   * A later TYPE_REMOVE re-add does not admit.
   */
  public function testLaterRemovePassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertCompileParameterHas(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      'mcp_sentinel_rogue_auth',
    );
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
  }

  /**
   * A later TYPE_AFTER_REMOVING re-add does not admit.
   */
  public function testLaterAfterRemovingPassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertCompileParameterHas(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      'mcp_sentinel_rogue_auth',
    );
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
  }

  /**
   * A decorator of the namespaced id does not admit.
   */
  public function testDecorateWithTestModuleOnIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertNamespacedHookRemoved();
    $this->assertCompileFlushedRejection('mcp_sentinel_rogue_auth');
  }

  /**
   * Rewiring factory and subscriber arguments does not admit.
   */
  public function testArgumentRewireIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertNamespacedHookRemoved();
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
  }

  /**
   * A spoofed Drupal\mcp_sentinel_test\ class is not honoured.
   */
  public function testSpoofedTestNamespaceClassIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertNamespacedHookRemoved();
    $this->assertCompileFlushedRejection('mcp_sentinel');
  }

  /**
   * Rewiring module_handler to NULL still denies and writes refused.
   */
  public function testNullModuleHandlerRewireIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
  }

  /**
   * Rewiring the handler to a stub that owns the rogue path is denied.
   */
  public function testStubModuleHandlerRewireIsDenied(): void {
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
  }

  /**
   * A stub handler does not block an owned ExtraClaims hook.
   *
   * Ownership is container.modules, so ExtraClaims is
   * admitted. Scopes and act stay stripped.
   */
  public function testStubModuleHandlerStillAdmitsOwnedExtension(): void {
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
    $this->assertSame('rogue-subject', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    $this->assertArrayNotHasKey('act', $ctx->keyClaims());
  }

  /**
   * A decorated live handler that lies about the test path is denied.
   *
   * The decorator is the live @module_handler. Ownership that
   * asks it admits the rewired rogue. container.modules does not.
   * The positive control proves the live handler's
   * mcp_sentinel_test path is the rogue fixture directory,
   * so the deny is against a real lie, not a missing module.
   */
  public function testDecoratedModuleHandlerRewireIsDenied(): void {
    $handler = $this->container->get('module_handler');
    $rogueFile = (new \ReflectionClass(
      McpRoguePrincipalAuthExtension::class,
    ))->getFileName();
    $this->assertIsString($rogueFile);
    $rogueDir = realpath(dirname($rogueFile));
    $reportedDir = realpath(
      DRUPAL_ROOT . '/' . $handler->getModule('mcp_sentinel_test')->getPath(),
    );
    $this->assertNotFalse($rogueDir);
    $this->assertNotFalse($reportedDir);
    $this->assertSame(
      $rogueDir,
      $reportedDir,
      'The live module handler must report mcp_sentinel_test at the rogue fixture directory.',
    );
    $this->assertStampedUnproxiedPatchDenied();
    $this->assertRuntimeRefusedAudit('mcp_sentinel_rogue_auth');
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

    try {
      $this->container->get('mcp_sentinel.principal_context_dispatcher')
        ->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
      $this->fail('A claimless PATCH must stay denied.');
    }
    catch (McpPrincipalContextDeniedException) {
    }
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
   * Point factory and subscriber at a rogue id and a lying handler.
   */
  private function registerStubHandler(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_bypass.rogue',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $container->register(
      'mcp_sentinel_bypass.stub_handler',
      StubOwningTestModuleHandler::class,
    )
      ->setPublic(TRUE)
      ->setArgument(0, new Reference('module_handler'));
    $rogue = new Reference('mcp_sentinel_bypass.rogue');
    $stub = new Reference('mcp_sentinel_bypass.stub_handler');
    $container->getDefinition('mcp_sentinel.principal_context_factory')
      ->setArgument(2, $rogue)
      ->setArgument(4, $stub);
    $container->getDefinition('mcp_sentinel.principal_context_subscriber')
      ->setArgument(2, $rogue)
      ->setArgument(3, $stub);
  }

  /**
   * Point factory and subscriber at ExtraClaims and a stub handler.
   */
  private function registerStubOwnedHandler(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_bypass.owned',
      McpTestExtraClaimsPrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $container->register(
      'mcp_sentinel_bypass.stub_handler',
      StubOwningTestModuleHandler::class,
    )
      ->setPublic(TRUE)
      ->setArgument(0, new Reference('module_handler'));
    $owned = new Reference('mcp_sentinel_bypass.owned');
    $stub = new Reference('mcp_sentinel_bypass.stub_handler');
    $container->getDefinition('mcp_sentinel.principal_context_factory')
      ->setArgument(2, $owned)
      ->setArgument(4, $stub);
    $container->getDefinition('mcp_sentinel.principal_context_subscriber')
      ->setArgument(2, $owned)
      ->setArgument(3, $stub);
  }

  /**
   * Decorate @module_handler and rewire the factory to the rogue.
   */
  private function registerDecoratedHandler(ContainerBuilder $container): void {
    $container->register(
      'mcp_sentinel_bypass.rogue',
      McpRoguePrincipalAuthExtension::class,
    )->setPublic(TRUE);
    $container->register(
      'mcp_sentinel_bypass.lying_handler',
      LyingTestModulePathHandler::class,
    )
      ->setPublic(TRUE)
      ->setDecoratedService('module_handler')
      ->setArgument(0, new Reference('mcp_sentinel_bypass.lying_handler.inner'));
    $rogue = new Reference('mcp_sentinel_bypass.rogue');
    $container->getDefinition('mcp_sentinel.principal_context_factory')
      ->setArgument(2, $rogue);
    $container->getDefinition('mcp_sentinel.principal_context_subscriber')
      ->setArgument(2, $rogue);
  }

  /**
   * Namespaced hook id is gone after compile.
   */
  private function assertNamespacedHookRemoved(): void {
    $id = McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID;
    $this->assertFalse($this->container->has($id));
  }

  /**
   * Compiled refusal list names this service, reason, and provider.
   *
   * @param string $serviceId
   *   Expected service id.
   * @param string $provider
   *   Expected provider module.
   */
  private function assertCompileParameterHas(
    string $serviceId,
    string $provider,
  ): void {
    $this->assertTrue(
      $this->container->hasParameter(McpPrincipalContextFactory::REJECTED_PARAMETER),
    );
    $rows = $this->container->getParameter(
      McpPrincipalContextFactory::REJECTED_PARAMETER,
    );
    $this->assertIsArray($rows);
    $found = FALSE;
    foreach ($rows as $row) {
      if (!is_array($row)) {
        continue;
      }
      if (($row['service'] ?? '') === $serviceId
        && ($row['reason'] ?? '') === 'refused'
        && ($row['provider'] ?? '') === $provider) {
        $found = TRUE;
        break;
      }
    }
    $this->assertTrue($found);
  }

  /**
   * Compile flush wrote service, refused, and this provider.
   *
   * @param string $provider
   *   Expected provider module.
   */
  private function assertCompileFlushedRejection(string $provider): void {
    $found = FALSE;
    foreach ($this->refusedAuditRows() as $metadata) {
      if (($metadata['service'] ?? '') === McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID
        && ($metadata['reason'] ?? '') === 'refused'
        && ($metadata['provider'] ?? '') === $provider) {
        $found = TRUE;
        break;
      }
    }
    $this->assertTrue($found);
  }

  /**
   * A refused row the compile flush cannot explain, with provider.
   *
   * @param string $provider
   *   Expected provider on the latest runtime row.
   */
  private function assertRuntimeRefusedAudit(string $provider): void {
    $compiled = [];
    if ($this->container->hasParameter(McpPrincipalContextFactory::REJECTED_PARAMETER)) {
      $rows = $this->container->getParameter(
        McpPrincipalContextFactory::REJECTED_PARAMETER,
      );
      if (is_array($rows)) {
        $compiled = $rows;
      }
    }
    $logged = $this->refusedAuditRows();
    $this->assertGreaterThan(
      count($compiled),
      count($logged),
      'Runtime recordRejection() must write a row the compile flush cannot explain.',
    );
    $latest = $logged === [] ? NULL : $logged[array_key_last($logged)];
    $this->assertIsArray($latest);
    $this->assertSame(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      $latest['service'] ?? '',
    );
    $this->assertSame('refused', $latest['reason'] ?? '');
    $this->assertSame($provider, $latest['provider'] ?? '');
  }

  /**
   * Decoded principal_auth_extension_rejected rows, oldest first.
   *
   * @return list<array<string, mixed>>
   *   Metadata arrays.
   */
  private function refusedAuditRows(): array {
    $result = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpPrincipalContextFactory::AUDIT_OPERATION)
      ->orderBy('l.id', 'ASC')
      ->execute();
    $decoded = [];
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    foreach ($result as $row) {
      $decoded[] = $logger->decodeMetadata((string) $row->metadata);
    }
    return $decoded;
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
