<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\EventSubscriber\McpPrincipalContextSubscriber;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
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
   * The built-in server must not freeze a claimless test-child request.
   *
   * Production cli-server and fpm-fcgi do not defer. A bearer still
   * seals on a test child.
   *
   * @covers ::deferClaimlessBuiltinServer
   */
  public function testBuiltinServerDefersOnlyClaimlessTestChild(): void {
    $claimless = Request::create('/jsonapi/node/page');
    $this->assertTrue(McpPrincipalContextSubscriber::deferClaimlessBuiltinServer(
      $claimless,
      new McpRoleFallbackEnvironment('cli-server', FALSE, TRUE),
    ));
    $this->assertFalse(McpPrincipalContextSubscriber::deferClaimlessBuiltinServer(
      $claimless,
      new McpRoleFallbackEnvironment('cli-server', FALSE, FALSE),
    ));
    $this->assertFalse(McpPrincipalContextSubscriber::deferClaimlessBuiltinServer(
      $claimless,
      new McpRoleFallbackEnvironment('fpm-fcgi', FALSE, TRUE),
    ));
    $bearer = Request::create('/jsonapi/node/page');
    $bearer->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
    ]);
    $this->assertFalse(McpPrincipalContextSubscriber::deferClaimlessBuiltinServer(
      $bearer,
      new McpRoleFallbackEnvironment('cli-server', FALSE, TRUE),
    ));
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
