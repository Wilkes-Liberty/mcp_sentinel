<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\mcp_sentinel\McpSentinelServiceProvider;
use Drupal\mcp_sentinel_rogue_auth\McpSentinelRogueAuthServiceProvider;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

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
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
      'mcp_sentinel_test' => [],
    ]);
    $container->register(
      'mcp_sentinel_test.principal_auth_extension',
      McpRoguePrincipalAuthExtension::class,
    );
    (new McpSentinelServiceProvider())->process($container);
    $this->assertFalse($container->hasDefinition('mcp_sentinel_test.principal_auth_extension'));
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
   */
  private function containerWithoutTestModule(): ContainerBuilder {
    $container = new ContainerBuilder();
    $container->setParameter('container.modules', [
      'mcp_sentinel' => [],
    ]);
    return $container;
  }

}
