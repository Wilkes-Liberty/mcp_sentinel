<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Drush\Commands\McpPrincipalContextCommands;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Drush PRE/POST_COMMAND_HOOK open a deny-only overlay per invocation.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Drush\Commands\McpPrincipalContextCommands
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextCommands::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextDrushCommandsTest extends UnitTestCase {

  /**
   * PreCommand and postCommand wrap one invocation's deny-only overlay.
   *
   * @covers ::preCommand
   * @covers ::postCommand
   */
  public function testHooksOpenDenyOnlyOverlay(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $commands = new McpPrincipalContextCommands($holder);
    $commands->preCommand();
    $this->assertTrue($holder->inJobScope());
    $this->assertNull($holder->get());
    $commands->postCommand();
    $this->assertFalse($holder->inJobScope());
    $this->assertNull($holder->get());
  }

}
