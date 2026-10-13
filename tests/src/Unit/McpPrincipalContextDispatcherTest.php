<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextGuard;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Leftover CLI is write-once; an overlay admit is always refused.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextDispatcher::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextDispatcherTest extends UnitTestCase {

  /**
   * A leftover bootstrap request keeps the first seal; overlay refuses.
   *
   * @covers ::admit
   */
  public function testLeftoverCliRequestKeepsFirstSealAndOverlayRefuses(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $guard = new McpPrincipalContextGuard();
    $guard->disableForTest();
    // The factory is final; build a real one over a mocked OAuth seam.
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory($stack, $oauth);
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
    $sealed = $holder->get();
    $this->assertInstanceOf(McpPrincipalContext::class, $sealed);
    $this->assertSame('human-1', $sealed->subject());
    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-2', 'agent-b'));
    $second = $dispatcher->admit([], 'tool-b');
    $this->assertSame($sealed, $second);
    $this->assertSame('human-1', $holder->get()?->subject());

    $job = new McpPrincipalContextJob($holder);
    $job->begin();
    try {
      $dispatcher->admit([], 'tool-c');
      $this->fail('An overlay admit must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $job->end();
    $this->assertSame($sealed, $holder->get());
  }

  /**
   * Validated claims that can compose a principal key.
   *
   * @return array<string, string>
   *   JWT-shaped claims.
   */
  private function claims(string $sub, string $azp): array {
    return [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => $sub,
      'azp' => $azp,
      'tenant' => 'tenant-a',
    ];
  }

}
