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
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dispatcher refuses under a deny-only job overlay.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextDispatcher::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextDispatcherTest extends UnitTestCase {

  /**
   * A second leftover CLI item under its own overlay does not reseal-refuse.
   *
   * @covers ::admit
   */
  public function testSecondCliItemUnderOwnScopeDoesNotResealRefuse(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $job = new McpPrincipalContextJob($holder);
    $dispatcher = $this->dispatcher($stack, $holder);

    $job->begin();
    try {
      $dispatcher->admit([], 'tool-a');
      $this->fail('The first overlay item must refuse.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertNotSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $job->end();

    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-2', 'agent-b'));
    $job->begin();
    try {
      $dispatcher->admit([], 'tool-b');
      $this->fail('The second overlay item must refuse.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertNotSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $job->end();
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * Deny() logs when the audit write fails and still throws the denial.
   *
   * @covers ::deny
   */
  public function testDenyLogsAuditWriteFailure(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal(new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-a',
      'agent-a',
      ['mcp_read'],
      'tenant-a',
      [],
      TRUE,
      $this->claims('human-1', 'agent-a'),
    ), $request);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->method('logAlways')->willThrowException(new \RuntimeException('audit down'));
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('error');
    $dispatcher = $this->dispatcher($stack, $holder, $audit, $logger);
    try {
      $dispatcher->admit(['user' => '2'], 'tool-a');
      $this->fail('A reserved identity argument must be denied.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        $e->reasonCode,
      );
    }
  }

  /**
   * Builds a dispatcher over a real factory and the given holder.
   */
  private function dispatcher(
    RequestStack $stack,
    McpPrincipalContextHolder $holder,
    ?McpAuditLogger $audit = NULL,
    ?LoggerInterface $logger = NULL,
  ): McpPrincipalContextDispatcher {
    $guard = new McpPrincipalContextGuard();
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory($stack, $oauth);
    return new McpPrincipalContextDispatcher(
      $factory,
      $stack,
      $guard,
      $holder,
      $audit ?? $this->createMock(McpAuditLogger::class),
      $logger ?? $this->createMock(LoggerInterface::class),
    );
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
