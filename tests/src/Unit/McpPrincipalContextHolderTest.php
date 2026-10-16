<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpJobScopeHandle;
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
   * A nested subrequest cannot replace an active parent's seal.
   *
   * Main → A (sealed P) → B (Q) must throw RESEAL_REFUSED. The
   * leftover fixture in kernel tests is reset in the test helper,
   * not by weakening this guard.
   *
   * @covers ::seal
   */
  public function testNestedSubrequestCannotReplaceParentSeal(): void {
    $stack = new RequestStack();
    $main = Request::create('/kernel');
    $parent = Request::create('/parent');
    $nested = Request::create('/nested');
    $stack->push($main);
    $stack->push($parent);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal($this->ctx('human-1', 'agent-a'), $parent);
    $stack->push($nested);
    try {
      $holder->seal($this->ctx('human-2', 'agent-b'), $nested);
      $this->fail('A nested subrequest must not replace a parent seal.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $stack->pop();
    $restored = $holder->get();
    $this->assertInstanceOf(McpPrincipalContext::class, $restored);
    $this->assertSame('human-1', $restored->subject());
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
    $this->assertTrue($holder->inJobScope());
    $stub->end();
    $this->assertSame($cron, $holder->get());
  }

  /**
   * LeaveJobScope() is refused without the matching enter handle.
   *
   * @covers ::enterJobScope
   * @covers ::leaveJobScope
   */
  public function testLeaveJobScopeRequiresMatchingHandle(): void {
    $holder = new McpPrincipalContextHolder(new RequestStack());
    $inner = $holder->enterJobScope();
    try {
      $holder->leaveJobScope(new McpJobScopeHandle());
      $this->fail('A forged handle must be refused.');
    }
    catch (\LogicException $e) {
      $this->assertStringContainsString(
        'matching enterJobScope',
        $e->getMessage(),
      );
    }
    $this->assertTrue($holder->inJobScope());
    $outer = $holder->enterJobScope();
    try {
      $holder->leaveJobScope($inner);
      $this->fail('An outer handle must not close the inner overlay.');
    }
    catch (\LogicException $e) {
      $this->assertStringContainsString(
        'matching enterJobScope',
        $e->getMessage(),
      );
    }
    $holder->leaveJobScope($outer);
    $this->assertTrue($holder->inJobScope());
    $holder->leaveJobScope($inner);
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * SealForJob() and resetForJob() are gone; mixed/object/parent count.
   *
   * Fails if any public method other than seal() can accept a
   * caller-built principal context, including mixed, object, or a
   * parent type of McpPrincipalContext.
   */
  public function testPublicMethodsDoNotAcceptCallerBuiltContext(): void {
    $class = new \ReflectionClass(McpPrincipalContextHolder::class);
    $this->assertFalse($class->hasMethod('sealForJob'));
    $this->assertFalse($class->hasMethod('resetForJob'));
    $accepted = [];
    foreach ($class->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
      if ($method->getDeclaringClass()->getName() !== $class->getName()) {
        continue;
      }
      if ($method->getName() === 'seal') {
        continue;
      }
      foreach ($method->getParameters() as $parameter) {
        if ($this->parameterAcceptsPrincipalContext($parameter)) {
          $accepted[] = $method->getName() . '::$' . $parameter->getName();
        }
      }
    }
    $this->assertSame([], $accepted);
  }

  /**
   * Whether a parameter is typed as or accepts McpPrincipalContext.
   *
   * Mixed, object, untyped, and parent types are treated as accepting.
   *
   * @param \ReflectionParameter $parameter
   *   The parameter.
   *
   * @return bool
   *   TRUE when the parameter can take a principal context.
   */
  private function parameterAcceptsPrincipalContext(\ReflectionParameter $parameter): bool {
    $type = $parameter->getType();
    if ($type === NULL) {
      return TRUE;
    }
    return $this->typeAcceptsPrincipalContext($type);
  }

  /**
   * Whether a reflected type includes McpPrincipalContext.
   *
   * @param \ReflectionType $type
   *   The parameter type.
   *
   * @return bool
   *   TRUE when the type includes McpPrincipalContext.
   */
  private function typeAcceptsPrincipalContext(\ReflectionType $type): bool {
    if ($type instanceof \ReflectionNamedType) {
      $name = $type->getName();
      if ($name === 'mixed' || $name === 'object') {
        return TRUE;
      }
      if ($name === McpPrincipalContext::class) {
        return TRUE;
      }
      return class_exists($name)
        && is_a(McpPrincipalContext::class, $name, TRUE);
    }
    if ($type instanceof \ReflectionUnionType
      || $type instanceof \ReflectionIntersectionType) {
      foreach ($type->getTypes() as $inner) {
        if ($this->typeAcceptsPrincipalContext($inner)) {
          return TRUE;
        }
      }
      return FALSE;
    }
    return FALSE;
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
