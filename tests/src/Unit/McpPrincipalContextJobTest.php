<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Support\McpJobScopeQueueStub;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Job helper opens a deny-only overlay around one CLI/queue item.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextJob
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextJob::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextJobTest extends UnitTestCase {

  /**
   * Run() hides any leftover and never stores a caller-built context.
   *
   * @covers ::run
   * @covers ::begin
   * @covers ::end
   */
  public function testRunHidesSealAroundTheItem(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $this->assertNull($holder->get());
    $job = new McpPrincipalContextJob($holder);
    $seen = $job->run(function () use ($holder): bool {
      $this->assertTrue($holder->inJobScope());
      $this->assertNull($holder->get());
      $holder->seal($this->ctx('human-2', 'agent-b'), 'ignored');
      $this->assertNull($holder->get());
      return $holder->inJobScope();
    });
    $this->assertTrue($seen);
    $this->assertFalse($holder->inJobScope());
    $this->assertNull($holder->get());
  }

  /**
   * Run() overlays a request seal and restores it after the item.
   *
   * @covers ::run
   * @covers ::begin
   * @covers ::end
   */
  public function testRunOverlaysHttpSealAndRestoresIt(): void {
    $stack = new RequestStack();
    $request = Request::create('/cron/test-key');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $cron = $this->ctx('cron-human', 'cron-client');
    $holder->seal($cron, $request);
    $job = new McpPrincipalContextJob($holder);
    $stub = new McpJobScopeQueueStub($job);
    $seen = $stub->processItem(function () use ($holder, $request): bool {
      $this->assertNull($holder->get());
      $holder->seal($this->ctx('job-human', 'job-client'), $request);
      $this->assertNull($holder->get());
      return $holder->inJobScope();
    });
    $this->assertTrue($seen);
    $this->assertSame($cron, $holder->get());
  }

  /**
   * A second queue item enters and leaves its own scope without reseal.
   *
   * @covers ::run
   */
  public function testSecondQueueItemDoesNotThrowResealRefused(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $job = new McpPrincipalContextJob($holder);
    $stub = new McpJobScopeQueueStub($job);
    $first = $stub->processItem(static fn (): string => 'one');
    $second = $stub->processItem(static fn (): string => 'two');
    $this->assertSame('one', $first);
    $this->assertSame('two', $second);
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * Release() unwinds leftover inner scopes and does not throw.
   *
   * @covers ::release
   */
  public function testReleaseUnwindsLeftoverInnerScopeAndLogs(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('error');
    $job = new McpPrincipalContextJob($holder, $logger);
    $handle = $job->begin();
    $job->begin();
    $closed = $job->release($handle);
    $this->assertSame(2, $closed);
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * A request seal is visible only outside a deny-only overlay.
   *
   * Live callers ask the dispatcher; the job helper no longer duplicates
   * that check. The holder still hides the seal while the overlay is open.
   *
   * @covers ::begin
   * @covers ::end
   */
  public function testRequestSealIsHiddenUnderOverlay(): void {
    $stack = new RequestStack();
    $request = Request::create('/cron/test-key');
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal($this->ctx('cron-human', 'cron-client'), $request);
    $job = new McpPrincipalContextJob($holder);
    $this->assertTrue($this->requestSealIsVisible($holder));
    $handle = $job->begin();
    $this->assertFalse($this->requestSealIsVisible($holder));
    $job->end($handle);
    $this->assertTrue($this->requestSealIsVisible($holder));
  }

  /**
   * End() is refused without the matching begin handle.
   *
   * @covers ::end
   */
  public function testEndRequiresMatchingHandle(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $job = new McpPrincipalContextJob($holder);
    $outer = $job->begin();
    $inner = $job->begin();
    try {
      $job->end($outer);
      $this->fail('end() must refuse a handle that is not innermost.');
    }
    catch (\LogicException $e) {
      $this->assertStringContainsString('matching begin()', $e->getMessage());
    }
    $this->assertTrue($holder->inJobScope());
    $job->end($inner);
    $job->end($outer);
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * BeginCarrying attaches kill-check keys without sealing identity.
   *
   * @covers ::beginCarrying
   */
  public function testBeginCarryingAttachesKeysWithoutSealingIdentity(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $job = new McpPrincipalContextJob($holder);
    $handle = $job->beginCarrying(
      'https://idp.example/realms/agents|subject-a|agent-a',
      'https://idp.example/realms/agents|subject-a',
      'tenant-a',
    );
    $this->assertTrue($holder->inJobScope());
    $this->assertNull($holder->get());
    $carried = $holder->carriedPrincipal();
    $this->assertNotNull($carried);
    $this->assertSame(
      'https://idp.example/realms/agents|subject-a|agent-a',
      $carried->principalKey,
    );
    $job->end($handle);
    $this->assertNull($holder->carriedPrincipal());
  }

  /**
   * Whether a request principal is visible outside any job overlay.
   *
   * Same predicate live callers used to ask the job helper for. The
   * dispatcher still owns that check; the job helper no longer does.
   */
  private function requestSealIsVisible(McpPrincipalContextHolder $holder): bool {
    return !$holder->inJobScope()
      && $holder->get() instanceof McpPrincipalContext;
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
