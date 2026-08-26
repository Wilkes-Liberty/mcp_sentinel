<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\EventSubscriber\McpReadinessAccessDeniedSubscriber;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Anonymous readiness AccessDenied becomes 403 JSON, not a login bounce.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\EventSubscriber\McpReadinessAccessDeniedSubscriber
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpReadinessAccessDeniedSubscriber::class)]
#[Group('mcp_sentinel')]
final class McpReadinessAccessDeniedSubscriberTest extends UnitTestCase {

  /**
   * An anonymous AccessDenied on readiness is 403 JSON, reason unauthenticated.
   *
   * @covers ::onException
   */
  public function testAnonymousReadinessAccessDeniedIsJson(): void {
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      'mcp_sentinel.readiness',
    );
    $this->subscriber(FALSE)->onException($event);

    $response = $event->getResponse();
    $this->assertInstanceOf(JsonResponse::class, $response);
    $this->assertSame(403, $response->getStatusCode());
    $this->assertSame('', $response->headers->get('Location') ?? '');
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('MCP access is denied.', $payload['error']);
    $this->assertSame('unauthenticated', $payload['reason']);
    $this->assertArrayNotHasKey('contract_ready', $payload);
    $this->assertTrue($event->isPropagationStopped());
  }

  /**
   * Authenticated AccessDenied is left for Drupal's normal 403 handling.
   *
   * @covers ::onException
   */
  public function testAuthenticatedAccessDeniedIsNotRewritten(): void {
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      'mcp_sentinel.readiness',
    );
    $this->subscriber(TRUE)->onException($event);
    $this->assertFalse($event->hasResponse());
    $this->assertFalse($event->isPropagationStopped());
  }

  /**
   * Other routes keep Drupal's default AccessDenied handling.
   *
   * @covers ::onException
   */
  public function testOtherRouteIsNotRewritten(): void {
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      'mcp_sentinel.context',
    );
    $this->subscriber(FALSE)->onException($event);
    $this->assertFalse($event->hasResponse());
  }

  /**
   * Non-AccessDenied exceptions are ignored.
   *
   * @covers ::onException
   */
  public function testOtherExceptionIsIgnored(): void {
    $event = $this->exceptionEvent(
      new NotFoundHttpException(),
      'mcp_sentinel.readiness',
    );
    $this->subscriber(FALSE)->onException($event);
    $this->assertFalse($event->hasResponse());
  }

  /**
   * Builds the subscriber around a stub current user.
   *
   * @param bool $authenticated
   *   Whether the stub account is authenticated.
   *
   * @return \Drupal\mcp_sentinel\EventSubscriber\McpReadinessAccessDeniedSubscriber
   *   The subscriber under test.
   */
  private function subscriber(bool $authenticated): McpReadinessAccessDeniedSubscriber {
    $account = $this->createMock(AccountProxyInterface::class);
    $account->method('isAuthenticated')->willReturn($authenticated);
    return new McpReadinessAccessDeniedSubscriber($account);
  }

  /**
   * Builds a kernel exception event for one route.
   *
   * @param \Throwable $exception
   *   The exception on the event.
   * @param string $route_name
   *   The request `_route` attribute.
   *
   * @return \Symfony\Component\HttpKernel\Event\ExceptionEvent
   *   The event.
   */
  private function exceptionEvent(\Throwable $exception, string $route_name): ExceptionEvent {
    $request = Request::create('/drupal-mcp/readiness');
    $request->attributes->set('_route', $route_name);
    return new ExceptionEvent(
      $this->createMock(HttpKernelInterface::class),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      $exception,
    );
  }

}