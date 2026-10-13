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
   * A leftover Drupal CLI request still requires resetForJob().
   *
   * @covers ::sealForJob
   * @covers ::resetForJob
   */
  public function testLeftoverCliRequestRequiresResetBetweenMessages(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->sealForJob($this->ctx('human-1', 'agent-a'));
    try {
      $holder->sealForJob($this->ctx('human-2', 'agent-b'));
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
    $holder->sealForJob($this->ctx('human-2', 'agent-b'));
    $this->assertSame('human-2', $holder->get()?->subject());
  }

  /**
   * An HTTP seal cannot replace a job that is already sealed.
   *
   * @covers ::seal
   * @covers ::sealForJob
   */
  public function testHttpSealDoesNotOverwriteJobPrincipal(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->sealForJob($this->ctx('human-1', 'agent-a'));
    try {
      $holder->seal($this->ctx('human-2', 'agent-b'), $request);
      $this->fail('An HTTP seal must not replace a sealed job principal.');
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
   * A job seal keeps a principal already sealed for the current request.
   *
   * @covers ::seal
   * @covers ::sealForJob
   */
  public function testSealForJobKeepsAlreadySealedHttpRequest(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $first = $this->ctx('human-1', 'agent-a');
    $holder->seal($first, $request);
    $holder->sealForJob($this->ctx('human-1', 'agent-a'));
    $this->assertSame($first, $holder->get());
  }

  /**
   * A job scope overlays a request seal and restores it after leave.
   *
   * @covers ::enterJobScope
   * @covers ::leaveJobScope
   * @covers ::sealForJob
   * @covers ::get
   */
  public function testJobScopeOverlaysRequestSealWithoutMutatingIt(): void {
    $stack = new RequestStack();
    $request = Request::create('/cron/test-key');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $cron = $this->ctx('cron-human', 'cron-client');
    $holder->seal($cron, $request);
    $this->assertSame($cron, $holder->get());

    $holder->enterJobScope();
    $this->assertTrue($holder->inJobScope());
    $this->assertNull($holder->get());
    $holder->sealForJob($this->ctx('job-human', 'job-client'));
    $this->assertSame('job-human', $holder->get()?->subject());

    $holder->leaveJobScope();
    $this->assertFalse($holder->inJobScope());
    $restored = $holder->get();
    $this->assertInstanceOf(McpPrincipalContext::class, $restored);
    $this->assertSame($cron, $restored);
    $this->assertSame('cron-human', $restored->subject());
  }

  /**
   * Sequential enterJobScope() without leave clears only the overlay.
   *
   * @covers ::enterJobScope
   * @covers ::sealForJob
   */
  public function testSequentialEnterJobScopeClearsOverlayOnly(): void {
    $stack = new RequestStack();
    $request = Request::create('/cron/test-key');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $cron = $this->ctx('cron-human', 'cron-client');
    $holder->seal($cron, $request);

    $holder->enterJobScope();
    $holder->sealForJob($this->ctx('job-1', 'job-client'));
    $holder->enterJobScope();
    $this->assertNull($holder->get());
    $holder->sealForJob($this->ctx('job-2', 'job-client'));
    $this->assertSame('job-2', $holder->get()?->subject());
    $holder->leaveJobScope();
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
