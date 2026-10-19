<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\mcp_sentinel\McpSentinelServiceProvider;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionOwnership;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel_rogue_auth\McpSentinelRogueAuthServiceProvider;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Compiler pass strips a re-added principal-auth hook.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\McpSentinelServiceProvider
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpSentinelServiceProvider::class)]
#[Group('mcp_sentinel')]
final class McpSentinelServiceProviderTest extends UnitTestCase {

  /**
   * The guard runs at BEFORE_OPTIMIZATION -1000 and AFTER_REMOVING min.
   *
   * @covers ::register
   */
  public function testOwnershipPassesAreRegisteredLast(): void {
    $container = new ContainerBuilder();
    (new McpSentinelServiceProvider())->register($container);
    $config = $container->getCompilerPassConfig();
    $before = $config->getBeforeOptimizationPasses();
    $after = $config->getAfterRemovingPasses();
    $this->assertNotEmpty(array_filter(
      $before,
      static fn (mixed $pass): bool => $pass instanceof McpSentinelServiceProvider,
    ));
    $this->assertNotEmpty(array_filter(
      $after,
      static fn (mixed $pass): bool => $pass instanceof McpSentinelServiceProvider,
    ));
  }

  /**
   * A later alter() re-add is stripped after every module alter().
   *
   * @covers ::process
   */
  public function testLateReAddIsStripped(): void {
    $container = $this->containerWithoutTestModule();
    $later = new McpSentinelRogueAuthServiceProvider();
    $later->alter($container);
    $this->assertTrue($container->hasDefinition('mcp_sentinel.principal_auth_extension'));
    $this->assertTrue($container->hasDefinition('mcp_sentinel_test.principal_auth_extension'));

    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse(
      $container->hasDefinition('mcp_sentinel.principal_auth_extension'),
    );
    $this->assertFalse(
      $container->hasDefinition('mcp_sentinel_test.principal_auth_extension'),
    );
  }

  /**
   * A foreign class on the namespaced id is stripped.
   *
   * @covers ::process
   */
  public function testForeignClassOnNamespacedIdIsStripped(): void {
    $container = $this->containerWithTestModule();
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpRoguePrincipalAuthExtension::class,
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasDefinition('mcp_sentinel_test.principal_auth_extension'));
  }

  /**
   * An alias on the namespaced id is stripped.
   *
   * @covers ::process
   */
  public function testAliasOnNamespacedIdIsStripped(): void {
    $container = $this->containerWithTestModule();
    $container->register(
      'rogue.extension',
      McpRoguePrincipalAuthExtension::class,
    );
    $container->setAlias(
      'mcp_sentinel_test.principal_auth_extension',
      'rogue.extension',
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasAlias('mcp_sentinel_test.principal_auth_extension'));
    $this->assertFalse($container->hasDefinition('rogue.extension'));
  }

  /**
   * A decorator of the namespaced id is stripped.
   *
   * @covers ::process
   */
  public function testDecoratorOnNamespacedIdIsStripped(): void {
    $container = $this->containerWithTestModule();
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpTestPrincipalAuthExtension::class,
    );
    $container->register(
      'rogue.decorator',
      McpRoguePrincipalAuthExtension::class,
    )->setDecoratedService('mcp_sentinel_test.principal_auth_extension');
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasDefinition('rogue.decorator'));
  }

  /**
   * A rewired factory argument is nulled.
   *
   * @covers ::process
   */
  public function testRewiredFactoryArgumentIsNulled(): void {
    $container = $this->containerWithoutTestModule();
    $container->register(
      'rogue.extension',
      McpRoguePrincipalAuthExtension::class,
    );
    $container->register(
      'mcp_sentinel.principal_context_factory',
      McpPrincipalContextFactory::class,
    )->setArguments([
      new Reference('request_stack'),
      new Reference('oauth'),
      new Reference('rogue.extension'),
    ]);
    (new McpSentinelServiceProvider())->process($container);
    $argument = $container->getDefinition('mcp_sentinel.principal_context_factory')
      ->getArgument(2);
    $this->assertNull($argument);
    $rejected = $container->getParameter(
      McpPrincipalAuthExtensionOwnership::REJECTED_PARAMETER,
    );
    $this->assertIsArray($rejected);
    $this->assertNotEmpty($rejected);
  }

  /**
   * The owned test-module class is kept.
   *
   * @covers ::process
   */
  public function testOwnedTestModuleDefinitionIsKept(): void {
    $container = $this->containerWithTestModule();
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpTestPrincipalAuthExtension::class,
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertTrue($container->hasDefinition('mcp_sentinel_test.principal_auth_extension'));
    $this->assertSame(
      McpTestPrincipalAuthExtension::class,
      $container->getDefinition('mcp_sentinel_test.principal_auth_extension')->getClass(),
    );
  }

  /**
   * Empty container used by a later module's alter().
   *
   * @return \Drupal\Core\DependencyInjection\ContainerBuilder
   *   Container without mcp_sentinel_test.
   */
  private function containerWithoutTestModule(): ContainerBuilder {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [
        'pathname' => $this->moduleInfoPath('mcp_sentinel'),
      ],
    ]);
    return $container;
  }

  /**
   * Container that lists the real mcp_sentinel_test path.
   *
   * @return \Drupal\Core\DependencyInjection\ContainerBuilder
   *   Container with mcp_sentinel_test pathname.
   */
  private function containerWithTestModule(): ContainerBuilder {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [
        'pathname' => $this->moduleInfoPath('mcp_sentinel'),
      ],
      'mcp_sentinel_test' => [
        'pathname' => $this->testModuleInfoPath(),
      ],
    ]);
    return $container;
  }

  /**
   * Absolute path to this module's info.yml.
   *
   * @param string $module
   *   Machine name.
   *
   * @return string
   *   Absolute info.yml path.
   */
  private function moduleInfoPath(string $module): string {
    return dirname(__DIR__, 3) . '/' . $module . '.info.yml';
  }

  /**
   * Absolute path to the test module's info.yml.
   *
   * @return string
   *   Absolute info.yml path.
   */
  private function testModuleInfoPath(): string {
    $file = (new \ReflectionClass(McpTestPrincipalAuthExtension::class))
      ->getFileName();
    $this->assertIsString($file);
    return dirname($file, 3) . '/mcp_sentinel_test.info.yml';
  }

}
