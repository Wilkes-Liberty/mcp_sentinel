<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionOwnership;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Ownership is the test module path, not a namespace prefix.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionOwnership
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalAuthExtensionOwnership::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalAuthExtensionOwnershipTest extends UnitTestCase {

  /**
   * The shipped test-module class is owned.
   *
   * @covers ::isAdmitted
   * @covers ::classIsOwned
   */
  public function testShippedTestModuleClassIsOwned(): void {
    $modules = $this->testModuleList();
    $this->assertTrue(McpPrincipalAuthExtensionOwnership::classIsOwned(
      McpTestPrincipalAuthExtension::class,
      $modules,
    ));
    $this->assertTrue(McpPrincipalAuthExtensionOwnership::isAdmitted(
      new McpTestPrincipalAuthExtension(),
      $modules,
    ));
  }

  /**
   * A class from another module is not owned.
   *
   * @covers ::isAdmitted
   * @covers ::classIsOwned
   */
  public function testForeignClassIsNotOwned(): void {
    $modules = $this->testModuleList();
    $this->assertFalse(McpPrincipalAuthExtensionOwnership::classIsOwned(
      McpRoguePrincipalAuthExtension::class,
      $modules,
    ));
    $this->assertFalse(McpPrincipalAuthExtensionOwnership::isAdmitted(
      new McpRoguePrincipalAuthExtension(),
      $modules,
    ));
  }

  /**
   * A PHPUnit mock is not owned.
   *
   * @covers ::isAdmitted
   */
  public function testMockIsNotOwned(): void {
    $mock = $this->createMock(McpPrincipalAuthExtensionInterface::class);
    $this->assertFalse(McpPrincipalAuthExtensionOwnership::isAdmitted(
      $mock,
      $this->testModuleList(),
    ));
  }

  /**
   * Provider of the shipped class is mcp_sentinel_test.
   *
   * @covers ::providerOfClass
   */
  public function testProviderOfShippedClass(): void {
    $this->assertSame(
      'mcp_sentinel_test',
      McpPrincipalAuthExtensionOwnership::providerOfClass(
        McpTestPrincipalAuthExtension::class,
        $this->testModuleList(),
      ),
    );
  }

  /**
   * container.modules listing the test module.
   *
   * @return array<string, array{pathname: string}>
   *   Pathnames.
   */
  private function testModuleList(): array {
    $file = (new \ReflectionClass(McpTestPrincipalAuthExtension::class))
      ->getFileName();
    $this->assertIsString($file);
    $info = dirname($file, 3) . '/mcp_sentinel_test.info.yml';
    $this->assertFileExists($info);
    return [
      'mcp_sentinel_test' => ['pathname' => $info],
    ];
  }

}
