<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Extension\Extension;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel\EventSubscriber\McpPrincipalContextSubscriber;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Subscriber keeps the sealed principal on a nested MAIN_REQUEST.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\EventSubscriber\McpPrincipalContextSubscriber
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextSubscriber::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextSubscriberTest extends UnitTestCase {

  /**
   * A nested MAIN_REQUEST must not 500 or replace the sealed principal.
   *
   * @covers ::onRequest
   */
  public function testNestedMainRequestKeepsSealedPrincipal(): void {
    $stack = new RequestStack();
    $main = Request::create('/mcp');
    $main->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $nested = Request::create('/nested');
    $nested->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-2', 'agent-b'));
    $stack->push($main);
    $holder = new McpPrincipalContextHolder($stack);
    $subscriber = new McpPrincipalContextSubscriber($this->factory($stack), $holder);
    $kernel = $this->createMock(HttpKernelInterface::class);

    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $main,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $first = $holder->get();
    $this->assertSame('human-1', $first?->subject());

    $stack->push($nested);
    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $nested,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $this->assertSame($first, $holder->get());
    $this->assertSame(
      $first,
      $nested->attributes->get(McpPrincipalContext::REQUEST_ATTRIBUTE),
    );
  }

  /**
   * A leftover CLI bootstrap request is not sealed.
   *
   * @covers ::onRequest
   */
  public function testLeftoverCliRequestIsNotSealed(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $subscriber = new McpPrincipalContextSubscriber($this->factory($stack), $holder);
    $kernel = $this->createMock(HttpKernelInterface::class);

    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $leftover,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $this->assertNull($holder->get());
    $this->assertFalse($leftover->attributes->has(McpPrincipalContext::REQUEST_ATTRIBUTE));
  }

  /**
   * The test-module hook can skip sealing a claimless request.
   *
   * Production evaluates the claimless predicate before consulting
   * the hook. Leftover CLI still applies when the hook is NULL.
   *
   * @covers ::onRequest
   */
  public function testAuthExtensionDefersClaimlessSeal(): void {
    $stack = new RequestStack();
    $claimless = Request::create('/jsonapi/node/page');
    $stack->push($claimless);
    $holder = new McpPrincipalContextHolder($stack);
    $subscriber = new McpPrincipalContextSubscriber(
      $this->factory($stack),
      $holder,
      new McpTestPrincipalAuthExtension(),
      $this->owningTestModuleHandler(),
    );
    $kernel = $this->createMock(HttpKernelInterface::class);
    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $claimless,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $this->assertNull($holder->get());
    $this->assertFalse($claimless->attributes->has(McpPrincipalContext::REQUEST_ATTRIBUTE));
  }

  /**
   * A bearer request is sealed even when the hook would defer.
   *
   * @covers ::onRequest
   */
  public function testAuthExtensionCannotDeferBearerSeal(): void {
    $stack = new RequestStack();
    $bearer = Request::create('/jsonapi/node/page');
    $bearer->attributes->set(
      McpPrincipalContext::CLAIMS_ATTRIBUTE,
      $this->claims('human-1', 'agent-a'),
    );
    $stack->push($bearer);
    $holder = new McpPrincipalContextHolder($stack);
    $extension = $this->createMock(McpPrincipalAuthExtensionInterface::class);
    $extension->expects($this->never())->method('deferClaimlessSeal');
    $subscriber = new McpPrincipalContextSubscriber(
      $this->factory($stack),
      $holder,
      $extension,
    );
    $kernel = $this->createMock(HttpKernelInterface::class);
    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $bearer,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $this->assertSame('human-1', $holder->get()?->subject());
  }

  /**
   * Runtime ownership runs before deferClaimlessSeal().
   *
   * @covers ::onRequest
   */
  public function testRogueExtensionCannotDeferClaimlessSeal(): void {
    $stack = new RequestStack();
    $claimless = Request::create('/jsonapi/node/page');
    $stack->push($claimless);
    $holder = new McpPrincipalContextHolder($stack);
    $extension = $this->createMock(McpPrincipalAuthExtensionInterface::class);
    $extension->expects($this->never())->method('deferClaimlessSeal');
    $modules = $this->createMock(ModuleHandlerInterface::class);
    $modules->method('moduleExists')->willReturn(FALSE);
    $modules->method('getModuleList')->willReturn([]);
    $subscriber = new McpPrincipalContextSubscriber(
      $this->factory($stack),
      $holder,
      $extension,
      $modules,
    );
    $kernel = $this->createMock(HttpKernelInterface::class);
    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $claimless,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $this->assertNull($holder->get());
  }

  /**
   * Handler stub that reports mcp_sentinel_test at its real path.
   */
  private function owningTestModuleHandler(): ModuleHandlerInterface {
    $info = dirname((new \ReflectionClass(McpTestPrincipalAuthExtension::class))->getFileName() ?: '', 3)
      . '/mcp_sentinel_test.info.yml';
    $module = $this->createMock(Extension::class);
    $module->method('getPathname')->willReturn($info);
    $module->method('getPath')->willReturn(dirname($info));
    $handler = $this->createMock(ModuleHandlerInterface::class);
    $handler->method('moduleExists')->willReturnCallback(
      static fn (string $name): bool => $name === 'mcp_sentinel_test',
    );
    $handler->method('getModule')->willReturn($module);
    $handler->method('getModuleList')->willReturn(['mcp_sentinel_test' => $module]);
    return $handler;
  }

  /**
   * A real factory (the class is final) over a mocked OAuth seam.
   */
  private function factory(RequestStack $stack): McpPrincipalContextFactory {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    return new McpPrincipalContextFactory($stack, $oauth);
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
