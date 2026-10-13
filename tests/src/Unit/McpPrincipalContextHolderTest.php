<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Support\McpJobScopeQueueStub;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Holder seals per request and hides that seal under a deny-only overlay.
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
   * A seal is hidden once its request has left the stack.
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
   * A leftover Drupal CLI request is write-once, like HTTP.
   *
   * @covers ::seal
   * @covers ::resetForJob
   */
  public function testLeftoverCliRequestIsWriteOnce(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $first = $this->ctx('human-1', 'agent-a');
    $holder->seal($first, $leftover);
    $holder->seal($this->ctx('human-2', 'agent-b'), $leftover);
    $this->assertSame($first, $holder->get());
    $this->expectException(\LogicException::class);
    $holder->resetForJob();
  }

  /**
   * ResetForJob() is refused while an HTTP request's own seal is current.
   *
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
   * Seal during an overlay is a no-op and does not mutate the request.
   *
   * @covers ::enterJobScope
   * @covers ::leaveJobScope
   * @covers ::seal
   * @covers ::get
   */
  public function testOverlaySealIsNoopAndRestoresRequestSeal(): void {
    $stack = new RequestStack();
    $request = Request::create('/cron/test-key');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $cron = $this->ctx('cron-human', 'cron-client');
    $holder->seal($cron, $request);

    $stub = new McpJobScopeQueueStub(new McpPrincipalContextJob($holder));
    $stub->begin();
    $this->assertTrue($holder->inJobScope());
    $hidden = $holder->get();
    $this->assertNull($hidden);
    $holder->seal($this->ctx('job-human', 'job-client'), $request);
    $stillHidden = $holder->get();
    $this->assertNull($stillHidden);

    $stub->end();
    $this->assertFalse($holder->inJobScope());
    $restored = $holder->get();
    $this->assertSame($cron, $restored);
    $this->assertSame('cron-human', $restored->subject());
  }

  /**
   * Sequential enterJobScope() stays in the overlay.
   *
   * @covers ::enterJobScope
   */
  public function testSequentialEnterJobScopeStaysInOverlay(): void {
    $stack = new RequestStack();
    $request = Request::create('/cron/test-key');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $cron = $this->ctx('cron-human', 'cron-client');
    $holder->seal($cron, $request);

    $stub = new McpJobScopeQueueStub(new McpPrincipalContextJob($holder));
    $stub->begin();
    $hidden = $holder->get();
    $this->assertNull($hidden);
    $stub->begin();
    $this->assertTrue($holder->inJobScope());
    $stillHidden = $holder->get();
    $this->assertNull($stillHidden);
    $stub->end();
    $this->assertSame($cron, $holder->get());
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
