<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Drush\Commands\McpPrincipalContextCommands;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Drush PRE/POST_COMMAND_HOOK reset the job principal per invocation.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Drush\Commands\McpPrincipalContextCommands
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextCommands::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextDrushCommandsTest extends UnitTestCase {

  /**
   * PreCommand and postCommand wrap one invocation's job overlay.
   *
   * @covers ::preCommand
   * @covers ::postCommand
   */
  public function testHooksResetJobPrincipal(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $commands = new McpPrincipalContextCommands($holder);
    $commands->preCommand();
    $this->assertTrue($holder->inJobScope());
    $this->assertNull($holder->get());
    $holder->sealForJob($this->ctx('human-1', 'agent-a'));
    $this->assertSame('human-1', $holder->get()?->subject());
    $commands->postCommand();
    $this->assertFalse($holder->inJobScope());
    $this->assertNull($holder->get());
  }

  /**
   * Builds a context that can compose a principal key.
   */
  private function ctx(string $sub, string $azp): McpPrincipalContext {
    return new McpPrincipalContext(
      'https://idp.example/realms/agents',
      $sub,
      $azp,
      $azp,
      ['mcp_read'],
      'tenant-a',
      [],
      TRUE,
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => $sub,
        'azp' => $azp,
      ],
    );
  }

}
