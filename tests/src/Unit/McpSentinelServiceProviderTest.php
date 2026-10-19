<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\mcp_sentinel\McpSentinelServiceProvider;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel_rogue_auth\McpSentinelRogueAuthServiceProvider;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Spoof\NsSpoofPrincipalAuthExtension;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder as SymfonyContainerBuilder;

/**
 * Late compiler pass strips a re-added principal-auth hook.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\McpSentinelServiceProvider
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpSentinelServiceProvider::class)]
#[Group('mcp_sentinel')]
final class McpSentinelServiceProviderTest extends UnitTestCase {

  /**
   * A later alter() re-add is stripped after every module alter().
   *
   * @covers ::process
   */
  public function testLateReAddIsStripped(): void {
    $container = $this->containerWithoutTestModule();
    $later = new McpSentinelRogueAuthServiceProvider();
    $later->alter($container);
    $this->assertTrue($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_LEGACY_ID));
    $this->assertTrue($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));

    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse(
      $container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_LEGACY_ID),
    );
    $this->assertFalse(
      $container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID),
    );
    $this->assertCompileRejectionRecorded($container);
  }

  /**
   * A foreign class on the namespaced id is stripped.
   *
   * @covers ::process
   */
  public function testForeignClassOnNamespacedIdIsStripped(): void {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
      'mcp_sentinel_test' => [],
    ]);
    $container->register(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      McpRoguePrincipalAuthExtension::class,
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
    $this->assertCompileRejectionRecorded($container);
  }

  /**
   * A foreign alias on the namespaced id is stripped.
   *
   * @covers ::process
   */
  public function testForeignAliasOnNamespacedIdIsStripped(): void {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
      'mcp_sentinel_test' => [],
    ]);
    $container->register(
      'mcp_sentinel_bypass.rogue',
      McpRoguePrincipalAuthExtension::class,
    );
    $container->setAlias(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      'mcp_sentinel_bypass.rogue',
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasAlias(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
    $this->assertFalse($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
    $this->assertCompileRejectionRecorded($container);
  }

  /**
   * The guard registers at TYPE_BEFORE_OPTIMIZATION / -1000.
   *
   * @covers ::register
   */
  public function testGuardPassRunsBeforeOptimization(): void {
    $container = new ContainerBuilder();
    (new McpSentinelServiceProvider())->register($container);
    $found = FALSE;
    foreach ($container->getCompilerPassConfig()->getBeforeOptimizationPasses() as $pass) {
      if ($pass instanceof McpSentinelServiceProvider) {
        $found = TRUE;
        break;
      }
    }
    $this->assertTrue($found);
    foreach ($container->getCompilerPassConfig()->getBeforeRemovingPasses() as $pass) {
      $this->assertNotInstanceOf(McpSentinelServiceProvider::class, $pass);
    }
  }

  /**
   * A non-Drupal builder is a programming error.
   *
   * @covers ::process
   */
  public function testProcessRejectsNonDrupalBuilder(): void {
    $this->expectException(\LogicException::class);
    (new McpSentinelServiceProvider())->process(new SymfonyContainerBuilder());
  }

  /**
   * The owned test-module class is kept.
   *
   * @covers ::process
   */
  public function testOwnedTestModuleDefinitionIsKept(): void {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
      'mcp_sentinel_test' => [],
    ]);
    $container->register(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      McpTestPrincipalAuthExtension::class,
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertTrue($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
    $this->assertSame(
      McpTestPrincipalAuthExtension::class,
      $container->getDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID)->getClass(),
    );
  }

  /**
   * A Drupal\mcp_sentinel_test\ class from a foreign path is stripped.
   *
   * @covers ::process
   */
  public function testForeignPathTestNamespaceClassIsStripped(): void {
    $this->loadNsSpoofClass();
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
      'mcp_sentinel_test' => [],
    ]);
    $container->register(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      NsSpoofPrincipalAuthExtension::class,
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
    $this->assertCompileRejectionRecorded($container);
  }

  /**
   * A same-type pass at -1 runs before the guard at -1000 and is stripped.
   *
   * @covers ::register
   * @covers ::process
   */
  public function testGuardPassOutrunsSameTypeNegativePriority(): void {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
    ]);
    (new McpSentinelServiceProvider())->register($container);
    $hostile = new class implements CompilerPassInterface {

      /**
       * {@inheritdoc}
       */
      public function process(SymfonyContainerBuilder $container): void {
        $container->register(
          McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
          McpRoguePrincipalAuthExtension::class,
        );
      }

    };
    $container->addCompilerPass(
      $hostile,
      PassConfig::TYPE_BEFORE_OPTIMIZATION,
      -1,
    );
    foreach ($container->getCompilerPassConfig()->getBeforeOptimizationPasses() as $pass) {
      if ($pass === $hostile || $pass instanceof McpSentinelServiceProvider) {
        $pass->process($container);
      }
    }
    $this->assertFalse($container->hasDefinition(McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID));
    $this->assertCompileRejectionRecorded($container);
  }

  /**
   * Empty container used by a later module's alter().
   */
  private function containerWithoutTestModule(): ContainerBuilder {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
    ]);
    return $container;
  }

  /**
   * Compile-time removal wrote a refused parameter row.
   */
  private function assertCompileRejectionRecorded(ContainerBuilder $container): void {
    $this->assertTrue($container->hasParameter(McpPrincipalContextFactory::REJECTED_PARAMETER));
    $rows = $container->getParameter(McpPrincipalContextFactory::REJECTED_PARAMETER);
    $this->assertIsArray($rows);
    $this->assertNotSame([], $rows);
    $this->assertSame(
      McpPrincipalContextFactory::AUTH_EXTENSION_SERVICE_ID,
      $rows[array_key_last($rows)]['service'] ?? $rows[0]['service'] ?? '',
    );
  }

  /**
   * Loads the foreign-path spoof.
   */
  private function loadNsSpoofClass(): void {
    if (!class_exists(NsSpoofPrincipalAuthExtension::class, FALSE)) {
      require_once dirname(__DIR__, 2) . '/modules/mcp_sentinel_ns_spoof/src/NsSpoofPrincipalAuthExtension.php';
    }
  }

}
