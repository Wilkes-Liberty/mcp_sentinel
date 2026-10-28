<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpKillEnforcerInterface;
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

    $first = $job->begin();
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
    $job->end($first);

    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-2', 'agent-b'));
    $second = $job->begin();
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
    $job->end($second);
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
   * A killed principal is refused with a generic deny; the row names the kill.
   *
   * @covers ::admit
   */
  public function testKilledPrincipalIsGenericDenyWithKillReasonOnRow(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('subject-a', 'agent-a'));
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal(new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'subject-a',
      'agent-a',
      'agent-a',
      ['mcp_read'],
      'tenant-a',
      [],
      FALSE,
      $this->claims('subject-a', 'agent-a'),
    ), $request);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta): bool {
        return ($meta['reason'] ?? '') === 'principal_killed';
      }),
    );
    $kill = $this->createMock(McpKillEnforcerInterface::class);
    $kill->method('isContextKilled')->willReturn(TRUE);
    $dispatcher = $this->dispatcher($stack, $holder, $audit, NULL, $kill);
    try {
      $dispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->fail('A killed principal must be refused at admit().');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
      $this->assertStringNotContainsString('killed', $e->getMessage());
    }
  }

  /**
   * Overlay and kill refusals are the same code, message, and exception class.
   *
   * @covers ::admit
   */
  public function testKilledAndOverlayRefusalsAreIndistinguishable(): void {
    $stack = new RequestStack();
    $holder = new McpPrincipalContextHolder($stack);
    $job = new McpPrincipalContextJob($holder);
    $handle = $job->beginCarrying(
      'https://idp.example/realms/agents|subject-a|agent-a',
      'https://idp.example/realms/agents|subject-a',
      'tenant-a',
    );

    $overlayMeta = [];
    $overlayAudit = $this->createMock(McpAuditLogger::class);
    $overlayAudit->method('logAlways')->willReturnCallback(
      static function (string $op, array $meta) use (&$overlayMeta): void {
        if ($op === 'denied_access') {
          $overlayMeta = $meta;
        }
      },
    );
    $overlayKill = $this->createMock(McpKillEnforcerInterface::class);
    $overlayKill->method('isContextKilled')->willReturn(FALSE);
    $overlayDispatcher = $this->dispatcher($stack, $holder, $overlayAudit, NULL, $overlayKill);
    try {
      $overlayDispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->fail('A job overlay must refuse.');
    }
    catch (McpPrincipalContextDeniedException $overlay) {
      $killMeta = [];
      $killAudit = $this->createMock(McpAuditLogger::class);
      $killAudit->method('logAlways')->willReturnCallback(
        static function (string $op, array $meta) use (&$killMeta): void {
          if ($op === 'denied_access') {
            $killMeta = $meta;
          }
        },
      );
      $killSwitch = $this->createMock(McpKillEnforcerInterface::class);
      $killSwitch->method('isContextKilled')->willReturn(TRUE);
      $killDispatcher = $this->dispatcher($stack, $holder, $killAudit, NULL, $killSwitch);
      try {
        $killDispatcher->admit(['note' => 'ok'], 'tool-a');
        $this->fail('A killed carried principal must be refused.');
      }
      catch (McpPrincipalContextDeniedException $killed) {
        $this->assertSame($overlay->reasonCode, $killed->reasonCode);
        $this->assertSame($overlay->getMessage(), $killed->getMessage());
        $this->assertSame(
          McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
          $overlay->reasonCode,
        );
        $this->assertSame(
          McpPrincipalContextDispatcher::GENERIC_REFUSAL,
          $overlay->getMessage(),
        );
        $this->assertSame('job_overlay', $overlayMeta['reason'] ?? '');
        $this->assertSame('principal_killed', $killMeta['reason'] ?? '');
        $this->assertSame('unverified', $killMeta['principal_key'] ?? '');
        $this->assertSame('unverified', $overlayMeta['principal_key'] ?? '');
      }
    }
    $job->end($handle);
  }

  /**
   * A token with azp=X and act.sub=X is refused and audited.
   *
   * The caller sees the generic missing-principal refusal so a spoof
   * is not a distinct agent-facing signal. The denied_access row
   * names actor_claim_collision.
   *
   * @covers ::assertDispatchAllowed
   */
  public function testAzpEqualToActSubIsDeniedAndAudited(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'shared-x',
      'act' => ['sub' => 'shared-x'],
      'tenant' => 'tenant-a',
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $collision = McpPrincipalKeyException::ACTOR_CLAIM_COLLISION;
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta) use ($collision): bool {
        return ($meta['reason'] ?? '') === $collision
          && ($meta['principal_key'] ?? '') === 'unverified'
          && ($meta['human_key'] ?? '') === 'unverified'
          && ($meta['principal_unverified'] ?? '') === $collision
          && ($meta['rule'] ?? '') === $collision
          && !str_contains((string) ($meta['explain'] ?? ''), 'secret');
      }),
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->fail('azp=X with act.sub=X must be denied.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
    }
  }

  /**
   * A token that omits the required surface scope is refused and audited.
   *
   * @covers ::assertDispatchAllowed
   */
  public function testRequiredScopeMissingIsRefused(): void {
    $stack = new RequestStack();
    $request = Request::create('/jsonapi/node/article');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'scopes' => ['mcp_read'],
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta): bool {
        return ($meta['reason'] ?? '') === 'required_scope_missing'
          && ($meta['principal_key'] ?? '') === 'https://idp.example/realms/agents|human-1|agent-client';
      }),
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
      $this->fail('A scope outside the token must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
        $e->reasonCode,
      );
    }
  }

  /**
   * A Paladin token that lists no scopes is refused.
   *
   * @covers ::assertDispatchAllowed
   */
  public function testPaladinEmptyScopesAreRefused(): void {
    $stack = new RequestStack();
    $request = Request::create('/jsonapi/node/article');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta): bool {
        return ($meta['reason'] ?? '') === 'required_scope_missing'
          && ($meta['principal_key'] ?? '') === 'https://idp.example/realms/agents|human-1|agent-client';
      }),
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_read']);
      $this->fail('A Paladin token with no scopes must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
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
    ?McpKillEnforcerInterface $kill = NULL,
  ): McpPrincipalContextDispatcher {
    $guard = new McpPrincipalContextGuard();
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory($stack, $oauth);
    if ($kill === NULL) {
      $kill = $this->createMock(McpKillEnforcerInterface::class);
      $kill->method('isContextKilled')->willReturn(FALSE);
    }
    return new McpPrincipalContextDispatcher(
      $factory,
      $stack,
      $guard,
      $holder,
      $audit ?? $this->createMock(McpAuditLogger::class),
      $logger ?? $this->createMock(LoggerInterface::class),
      $kill,
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
