<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Job helper clears the holder around one CLI/queue item.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextJob
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextJob::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextJobTest extends UnitTestCase {

  /**
   * Run() resets before and after the item so a leftover seal cannot stick.
   *
   * @covers ::run
   * @covers ::begin
   * @covers ::end
   */
  public function testRunClearsSealAroundTheItem(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $holder->sealForJob($this->ctx('human-1', 'agent-a'));
    $this->assertSame('human-1', $holder->get()?->subject());
    $job = new McpPrincipalContextJob($holder);
    $seen = $job->run(function () use ($holder): string {
      $this->assertNull($holder->get());
      $holder->sealForJob($this->ctx('human-2', 'agent-b'));
      return (string) $holder->get()?->subject();
    });
    $this->assertSame('human-2', $seen);
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
    $seen = $job->run(function () use ($holder): string {
      $this->assertNull($holder->get());
      $holder->sealForJob($this->ctx('job-human', 'job-client'));
      return (string) $holder->get()?->subject();
    });
    $this->assertSame('job-human', $seen);
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
