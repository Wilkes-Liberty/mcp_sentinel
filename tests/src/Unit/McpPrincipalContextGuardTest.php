<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpPrincipalContextGuard;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Guard disable is instance-only and PHPUnit-gated.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextGuard
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextGuard::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextGuardTest extends UnitTestCase {

  /**
   * Production default is on; disableForTest works under PHPUnit.
   *
   * @covers ::required
   * @covers ::disableForTest
   */
  public function testDisableForTestIsHonouredUnderPhpunit(): void {
    $guard = new McpPrincipalContextGuard();
    $this->assertTrue($guard->required());
    $guard->disableForTest();
    $this->assertFalse($guard->required());
    $this->assertTrue(
      defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_PHAR__'),
    );
    putenv('MCP_TEST_DISABLE_PRINCIPAL_CONTEXT_GUARD=1');
    putenv('PHPUNIT=1');
    $this->assertTrue((new McpPrincipalContextGuard())->required());
    putenv('MCP_TEST_DISABLE_PRINCIPAL_CONTEXT_GUARD');
    putenv('PHPUNIT');
  }

}
