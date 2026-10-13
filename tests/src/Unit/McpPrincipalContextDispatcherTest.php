<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextGuard;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dispatcher uses sealForJob() for leftover Drupal CLI requests.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextDispatcher::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextDispatcherTest extends UnitTestCase {

  /**
   * A leftover bootstrap request still requires resetForJob() per message.
   *
   * @covers ::admit
   */
  public function testLeftoverCliRequestSecondAdmitIsRefused(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $guard = new McpPrincipalContextGuard();
    $guard->disableForTest();
    $factory = $this->createMock(McpPrincipalContextFactory::class);
    $factory->method('fromCurrentRequest')->willReturnOnConsecutiveCalls(
      $this->ctx('human-1', 'agent-a'),
      $this->ctx('human-2', 'agent-b'),
      $this->ctx('human-2', 'agent-b'),
    );
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways');
    $dispatcher = new McpPrincipalContextDispatcher(
      $factory,
      $stack,
      $guard,
      $holder,
      $audit,
    );

    $dispatcher->admit([], 'tool-a');
    $this->assertSame('human-1', $holder->get()?->subject());
    try {
      $dispatcher->admit([], 'tool-b');
      $this->fail('A leftover CLI request must not reuse the first principal.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $this->assertSame('human-1', $holder->get()?->subject());
    $holder->resetForJob();
    $dispatcher->admit([], 'tool-b');
    $this->assertSame('human-2', $holder->get()?->subject());
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
