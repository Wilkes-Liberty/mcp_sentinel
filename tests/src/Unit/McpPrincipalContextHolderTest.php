<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Holder seals per request and requires resetForJob() on CLI workers.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextHolder::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextHolderTest extends UnitTestCase {

  /**
   * A subrequest cannot reseal a different principal.
   *
   * @covers ::seal
   */
  public function testSubrequestDifferentPrincipalIsRefused(): void {
    $stack = new RequestStack();
    $main = Request::create('/mcp');
    $sub = Request::create('/sub');
    $stack->push($main);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal($this->ctx('human-1', 'agent-a'), $main);
    $stack->push($sub);
    try {
      $holder->seal($this->ctx('human-2', 'agent-b'), $sub);
      $this->fail('A different principal in a subrequest must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $this->assertSame('human-1', $holder->get()?->subject());
  }

  /**
   * A subrequest with the same principal keeps the parent seal.
   *
   * @covers ::seal
   */
  public function testSubrequestSamePrincipalKeepsParent(): void {
    $stack = new RequestStack();
    $main = Request::create('/mcp');
    $sub = Request::create('/sub');
    $stack->push($main);
    $holder = new McpPrincipalContextHolder($stack);
    $first = $this->ctx('human-1', 'agent-a');
    $holder->seal($first, $main);
    $stack->push($sub);
    $holder->seal($this->ctx('human-1', 'agent-a'), $sub);
    $this->assertSame($first, $holder->get());
  }

  /**
   * A new main request replaces the previous request's seal.
   *
   * @covers ::seal
   */
  public function testNewMainRequestReplacesSeal(): void {
    $stack = new RequestStack();
    $first = Request::create('/one');
    $stack->push($first);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal($this->ctx('human-1', 'agent-a'), $first);
    $stack->pop();
    $second = Request::create('/two');
    $stack->push($second);
    $holder->seal($this->ctx('human-2', 'agent-b'), $second);
    $this->assertSame('human-2', $holder->get()?->subject());
  }

  /**
   * get() does not return a principal after its request leaves the stack.
   *
   * @covers ::get
   */
  public function testGetIgnoresSealFromRequestNoLongerOnStack(): void {
    $stack = new RequestStack();
    $first = Request::create('/one');
    $stack->push($first);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal($this->ctx('human-1', 'agent-a'), $first);
    $stack->pop();
    $this->assertNull($holder->get());
    $second = Request::create('/two');
    $stack->push($second);
    $this->assertNull($holder->get());
    $holder->seal($this->ctx('human-2', 'agent-b'), $second);
    $this->assertSame('human-2', $holder->get()?->subject());
  }

  /**
   * A CLI worker must resetForJob() between messages.
   *
   * @covers ::sealForJob
   * @covers ::resetForJob
   */
  public function testResetForJobIsRefusedDuringRequest(): void {
    $stack = new RequestStack();
    $stack->push(Request::create('/mcp', 'POST'));
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal($this->ctx('human-1', 'agent-client'), $stack->getCurrentRequest());
    $this->expectException(\LogicException::class);
    $holder->resetForJob();
  }

  /**
   * A second CLI seal without resetForJob() is refused.
   */
  public function testCliJobRequiresResetBetweenMessages(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $holder->sealForJob($this->ctx('human-1', 'agent-a'));
    try {
      $holder->sealForJob($this->ctx('human-2', 'agent-b'));
      $this->fail('A second CLI seal without resetForJob must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $holder->resetForJob();
    $holder->sealForJob($this->ctx('human-2', 'agent-b'));
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
