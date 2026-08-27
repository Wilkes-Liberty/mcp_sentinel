<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\EventSubscriber\McpReadinessAccessDeniedSubscriber;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Kernel: governed /drupal-mcp/* deny is JSON both ways (403 and 401).
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\EventSubscriber\McpReadinessAccessDeniedSubscriber
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpReadinessAccessDeniedSubscriber::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpGovernedPathAuthExceptionTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Anonymous AccessDenied on readiness is 403 JSON (the existing deny shape).
   */
  public function testAnonymousReadinessAccessDeniedIsJson(): void {
    $event = $this->dispatch(
      new AccessDeniedHttpException(),
      '/drupal-mcp/readiness',
      'mcp_sentinel.readiness',
    );
    $this->assertRefusal($event, 403, NULL);
  }

  /**
   * Invalid-bearer 401 on readiness is JSON and keeps WWW-Authenticate.
   */
  public function testReadinessUnauthorizedIsJsonWithChallenge(): void {
    $challenge = 'Bearer realm="OAuth", error="access_denied"';
    $event = $this->dispatch(
      new UnauthorizedHttpException($challenge, 'Unauthorized'),
      '/drupal-mcp/readiness',
      'mcp_sentinel.readiness',
    );
    $this->assertRefusal($event, 401, $challenge);
  }

  /**
   * Invalid-bearer 401 on /drupal-mcp/context is the same JSON shape.
   */
  public function testContextUnauthorizedIsJsonWithChallenge(): void {
    $challenge = 'Bearer realm="OAuth", error="access_denied"';
    $event = $this->dispatch(
      new UnauthorizedHttpException($challenge, 'Unauthorized'),
      '/drupal-mcp/context',
      'mcp_sentinel.context',
    );
    $this->assertRefusal($event, 401, $challenge);
  }

  /**
   * The public health probe is not rewritten.
   */
  public function testHealthUnauthorizedIsNotRewritten(): void {
    $event = $this->dispatch(
      new UnauthorizedHttpException('Bearer realm="OAuth"', 'Unauthorized'),
      '/drupal-mcp/health',
      'mcp_sentinel.health',
    );
    $this->assertFalse($event->hasResponse());
    $this->assertFalse($event->isPropagationStopped());
  }

  /**
   * Dispatches the exception through the container subscriber.
   *
   * @param \Throwable $exception
   *   The exception to rewrite.
   * @param string $path
   *   Request path info.
   * @param string $route_name
   *   The `_route` attribute.
   *
   * @return \Symfony\Component\HttpKernel\Event\ExceptionEvent
   *   The event after the subscriber ran.
   */
  private function dispatch(\Throwable $exception, string $path, string $route_name): ExceptionEvent {
    $request = Request::create($path);
    $request->attributes->set('_route', $route_name);
    $event = new ExceptionEvent(
      $this->container->get('http_kernel'),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      $exception,
    );
    /** @var \Drupal\mcp_sentinel\EventSubscriber\McpReadinessAccessDeniedSubscriber $subscriber */
    $subscriber = $this->container->get('mcp_sentinel.readiness_access_denied_subscriber');
    $subscriber->onException($event);
    return $event;
  }

  /**
   * Asserts the JSON refusal body and optional WWW-Authenticate header.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The event after the subscriber ran.
   * @param int $status
   *   Expected HTTP status.
   * @param string|null $challenge
   *   Expected WWW-Authenticate value, or NULL when the header must be absent.
   */
  private function assertRefusal(ExceptionEvent $event, int $status, ?string $challenge): void {
    $response = $event->getResponse();
    $this->assertInstanceOf(JsonResponse::class, $response);
    $this->assertSame($status, $response->getStatusCode());
    $this->assertSame('', $response->headers->get('Location') ?? '');
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('MCP access is denied.', $payload['error']);
    $this->assertSame('unauthenticated', $payload['reason']);
    $this->assertArrayNotHasKey('contract_ready', $payload);
    $this->assertTrue($event->isPropagationStopped());
    if ($challenge === NULL) {
      $this->assertNull($response->headers->get('WWW-Authenticate'));
      return;
    }
    $this->assertSame($challenge, $response->headers->get('WWW-Authenticate'));
  }

}
