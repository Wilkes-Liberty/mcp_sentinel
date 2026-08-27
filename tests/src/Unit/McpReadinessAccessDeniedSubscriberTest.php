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
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Governed /drupal-mcp/* auth denies become JSON, not HTML.
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
   * An invalid-bearer 401 on readiness is JSON and keeps WWW-Authenticate.
   *
   * @covers ::onException
   */
  public function testReadinessUnauthorizedKeepsWwwAuthenticate(): void {
    $challenge = 'Bearer realm="OAuth", error="access_denied"';
    $event = $this->exceptionEvent(
      new UnauthorizedHttpException($challenge, 'Unauthorized'),
      'mcp_sentinel.readiness',
    );
    $this->subscriber(FALSE)->onException($event);

    $response = $event->getResponse();
    $this->assertInstanceOf(JsonResponse::class, $response);
    $this->assertSame(401, $response->getStatusCode());
    $this->assertSame($challenge, $response->headers->get('WWW-Authenticate'));
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('MCP access is denied.', $payload['error']);
    $this->assertSame('unauthenticated', $payload['reason']);
    $this->assertTrue($event->isPropagationStopped());
  }

  /**
   * An invalid-bearer 401 on /drupal-mcp/context is the same JSON shape.
   *
   * @covers ::onException
   */
  public function testContextUnauthorizedIsJson(): void {
    $challenge = 'Bearer realm="OAuth"';
    $event = $this->exceptionEvent(
      new UnauthorizedHttpException($challenge, 'Unauthorized'),
      'mcp_sentinel.context',
      '/drupal-mcp/context',
    );
    $this->subscriber(TRUE)->onException($event);

    $response = $event->getResponse();
    $this->assertInstanceOf(JsonResponse::class, $response);
    $this->assertSame(401, $response->getStatusCode());
    $this->assertSame($challenge, $response->headers->get('WWW-Authenticate'));
  }

  /**
   * The public health probe is not rewritten.
   *
   * @covers ::onException
   */
  public function testHealthUnauthorizedIsNotRewritten(): void {
    $event = $this->exceptionEvent(
      new UnauthorizedHttpException('Bearer realm="OAuth"', 'Unauthorized'),
      'mcp_sentinel.health',
      '/drupal-mcp/health',
    );
    $this->subscriber(FALSE)->onException($event);
    $this->assertFalse($event->hasResponse());
    $this->assertFalse($event->isPropagationStopped());
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
      '/drupal-mcp/context',
    );
    $this->subscriber(FALSE)->onException($event);
    $this->assertFalse($event->hasResponse());
  }

  /**
   * Non-auth exceptions are ignored.
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
   * @param string $path
   *   The request path.
   *
   * @return \Symfony\Component\HttpKernel\Event\ExceptionEvent
   *   The event.
   */
  private function exceptionEvent(\Throwable $exception, string $route_name, string $path = '/drupal-mcp/readiness'): ExceptionEvent {
    $request = Request::create($path);
    $request->attributes->set('_route', $route_name);
    return new ExceptionEvent(
      $this->createMock(HttpKernelInterface::class),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      $exception,
    );
  }

}
