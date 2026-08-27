<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Rewrites governed /drupal-mcp/* auth denies to JSON, not an HTML page.
 *
 * Two shapes, same refusal body:
 * - Anonymous AccessDenied on readiness becomes 403 JSON so a 403-to-login
 *   converter cannot bounce fetch (DEV-435 / 2.13.2).
 * - Authentication 401 on /drupal-mcp/* (except the public health probe)
 *   becomes the same JSON, keeping WWW-Authenticate (d.o #3619396). An
 *   invalid bearer used to render core's HTML Unauthorized page.
 */
final class McpReadinessAccessDeniedSubscriber implements EventSubscriberInterface {

  public function __construct(
    private readonly AccountProxyInterface $currentUser,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Before user AccessDeniedSubscriber (75) and typical 403-to-login
    // converters, so this route never becomes Location /user/login. Also
    // before DefaultExceptionHtmlSubscriber, so a 401 is JSON not HTML.
    return [
      KernelEvents::EXCEPTION => ['onException', 100],
    ];
  }

  /**
   * Rewrites governed-path auth failures to the JSON refusal shape.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The exception event.
   */
  public function onException(ExceptionEvent $event): void {
    $path = $event->getRequest()->getPathInfo();
    if (!$this->isGovernedMcpPath($path)) {
      return;
    }

    $exception = $event->getThrowable();
    if ($this->isUnauthorized($exception)) {
      $headers = $this->refusalHeaders();
      $challenge = $this->wwwAuthenticate($exception);
      if ($challenge !== NULL) {
        $headers['WWW-Authenticate'] = $challenge;
      }
      $this->refuse($event, 401, $headers);
      return;
    }

    if (!$exception instanceof AccessDeniedHttpException) {
      return;
    }
    if ($this->currentUser->isAuthenticated()) {
      return;
    }
    $route_name = $event->getRequest()->attributes->get('_route');
    if ($route_name !== 'mcp_sentinel.readiness') {
      return;
    }

    $this->refuse($event, 403, $this->refusalHeaders());
  }

  /**
   * Whether this path is a governed MCP HTTP route, not the health probe.
   *
   * @param string $path
   *   The request path info.
   *
   * @return bool
   *   TRUE when the path is under /drupal-mcp/ and is not health.
   */
  private function isGovernedMcpPath(string $path): bool {
    if ($path === '/drupal-mcp/health' || str_starts_with($path, '/drupal-mcp/health/')) {
      return FALSE;
    }
    return $path === '/drupal-mcp' || str_starts_with($path, '/drupal-mcp/');
  }

  /**
   * Whether the throwable is an HTTP 401.
   *
   * @param \Throwable $exception
   *   The exception on the kernel event.
   *
   * @return bool
   *   TRUE when the exception is an HTTP 401.
   */
  private function isUnauthorized(\Throwable $exception): bool {
    if ($exception instanceof UnauthorizedHttpException) {
      return TRUE;
    }
    return $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 401;
  }

  /**
   * WWW-Authenticate value from the exception, if present.
   *
   * @param \Throwable $exception
   *   The exception on the kernel event.
   *
   * @return string|null
   *   The challenge string, or NULL when the header is absent.
   */
  private function wwwAuthenticate(\Throwable $exception): ?string {
    if (!$exception instanceof HttpExceptionInterface) {
      return NULL;
    }
    foreach ($exception->getHeaders() as $name => $value) {
      if (strcasecmp((string) $name, 'WWW-Authenticate') === 0) {
        if (is_array($value)) {
          $value = $value[0] ?? '';
        }
        $value = (string) $value;
        return $value === '' ? NULL : $value;
      }
    }
    return NULL;
  }

  /**
   * Headers shared by every JSON refusal on this path.
   *
   * @return array<string, string>
   *   Cache and content-type headers for the JSON body.
   */
  private function refusalHeaders(): array {
    return [
      'Cache-Control' => 'private, no-store',
      'X-Content-Type-Options' => 'nosniff',
    ];
  }

  /**
   * Sets the JSON refusal and stops further exception subscribers.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The exception event.
   * @param int $status
   *   HTTP status (401 or 403).
   * @param array<string, string> $headers
   *   Response headers.
   */
  private function refuse(ExceptionEvent $event, int $status, array $headers): void {
    $event->setResponse(new JsonResponse([
      'error' => 'MCP access is denied.',
      'reason' => McpGovernanceReadinessReason::Unauthenticated->value,
    ], $status, $headers));
    $event->stopPropagation();
  }

}
