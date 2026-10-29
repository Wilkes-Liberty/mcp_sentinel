<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\EventSubscriber\McpSealedTokenRevealCsrfDenySubscriber;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * CSRF 403 on the reveal POST writes one denied row and stays 403.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\EventSubscriber\McpSealedTokenRevealCsrfDenySubscriber
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpSealedTokenRevealCsrfDenySubscriber::class)]
#[Group('mcp_sentinel')]
final class McpSealedTokenRevealCsrfDenySubscriberTest extends UnitTestCase {

  /**
   * A privileged CSRF 403 writes exactly one denied row.
   *
   * @covers ::onException
   */
  public function testAccessDeniedOnRevealPostWritesDeniedRow(): void {
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      McpSealedTokenRevealCsrfDenySubscriber::OPERATION,
      $this->callback(static function (array $metadata): bool {
        $encoded = json_encode($metadata);
        $route = McpSealedTokenRevealCsrfDenySubscriber::ROUTE;
        return ($metadata['reason'] ?? '') === 'csrf_invalid'
          && ($metadata['route'] ?? '') === $route
          && ($metadata['uid'] ?? NULL) === 7
          && is_string($encoded)
          && !str_contains($encoded, 'mcs1.')
          && !array_key_exists('token', $metadata);
      }),
    );
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      McpSealedTokenRevealCsrfDenySubscriber::ROUTE,
    );
    $this->subscriber($audit, TRUE, 7)->onException($event);
    $this->assertFalse($event->hasResponse());
  }

  /**
   * Exception then 403 response still write only one row.
   *
   * @covers ::onException
   * @covers ::onResponse
   */
  public function testExceptionAndResponseDoNotDoubleWrite(): void {
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways');
    $request = $this->revealPostRequest();
    $subscriber = $this->subscriber($audit, TRUE, 3);
    $kernel = $this->createMock(HttpKernelInterface::class);
    $exceptionEvent = new ExceptionEvent(
      $kernel,
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      new AccessDeniedHttpException(),
    );
    $subscriber->onException($exceptionEvent);
    $responseEvent = new ResponseEvent(
      $kernel,
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      new Response('', 403),
    );
    $subscriber->onResponse($responseEvent);
    $this->assertSame(403, $responseEvent->getResponse()->getStatusCode());
  }

  /**
   * An audit-write failure leaves the 403 in place.
   *
   * @covers ::onException
   */
  public function testAuditFailureKeepsAccessDenied(): void {
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->method('logAlways')
      ->willThrowException(new \RuntimeException('audit down'));
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('error');
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      McpSealedTokenRevealCsrfDenySubscriber::ROUTE,
    );
    $this->subscriber($audit, TRUE, 4, $logger)->onException($event);
    $this->assertFalse($event->hasResponse());
    $this->assertInstanceOf(
      AccessDeniedHttpException::class,
      $event->getThrowable(),
    );
  }

  /**
   * Other routes are ignored.
   *
   * @covers ::onException
   */
  public function testOtherRouteIsIgnored(): void {
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->never())->method('logAlways');
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      McpSealedTokenRevealCsrfDenySubscriber::GET_ROUTE,
    );
    $this->subscriber($audit, TRUE, 2)->onException($event);
  }

  /**
   * Permission denials are not csrf_invalid.
   *
   * @covers ::onException
   */
  public function testUnprivilegedAccessDeniedIsIgnored(): void {
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->never())->method('logAlways');
    $event = $this->exceptionEvent(
      new AccessDeniedHttpException(),
      McpSealedTokenRevealCsrfDenySubscriber::ROUTE,
    );
    $this->subscriber($audit, FALSE, 0)->onException($event);
  }

  /**
   * Non-403 exceptions are ignored.
   *
   * @covers ::onException
   */
  public function testOtherExceptionIsIgnored(): void {
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->never())->method('logAlways');
    $event = $this->exceptionEvent(
      new NotFoundHttpException(),
      McpSealedTokenRevealCsrfDenySubscriber::ROUTE,
    );
    $this->subscriber($audit, TRUE, 2)->onException($event);
  }

  /**
   * Builds the subscriber around stubs.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $audit
   *   Audit logger stub.
   * @param bool $privileged
   *   Whether the actor may administer MCP Sentinel.
   * @param int $uid
   *   Acting uid.
   * @param \Psr\Log\LoggerInterface|null $logger
   *   Optional logger stub.
   *
   * @return \Drupal\mcp_sentinel\EventSubscriber\McpSealedTokenRevealCsrfDenySubscriber
   *   The subscriber under test.
   */
  private function subscriber(
    McpAuditLogger $audit,
    bool $privileged,
    int $uid,
    ?LoggerInterface $logger = NULL,
  ): McpSealedTokenRevealCsrfDenySubscriber {
    $account = $this->createMock(AccountProxyInterface::class);
    $account->method('hasPermission')->willReturn($privileged);
    $account->method('id')->willReturn($uid);
    return new McpSealedTokenRevealCsrfDenySubscriber(
      $audit,
      $account,
      $logger ?? $this->createMock(LoggerInterface::class),
    );
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
  private function exceptionEvent(
    \Throwable $exception,
    string $route_name,
  ): ExceptionEvent {
    $request = $this->revealPostRequest($route_name);
    return new ExceptionEvent(
      $this->createMock(HttpKernelInterface::class),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      $exception,
    );
  }

  /**
   * Builds a POST request for a reveal route.
   *
   * @param string $route_name
   *   The request `_route` attribute.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The request.
   */
  private function revealPostRequest(
    string $route_name = McpSealedTokenRevealCsrfDenySubscriber::ROUTE,
  ): Request {
    $request = Request::create(
      '/admin/config/services/mcp-sentinel/tokens/reveal',
      'POST',
    );
    $request->attributes->set('_route', $route_name);
    return $request;
  }

}
