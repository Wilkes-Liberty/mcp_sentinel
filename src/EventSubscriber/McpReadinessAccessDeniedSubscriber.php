<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Turns anonymous readiness AccessDenied into 403 JSON, not a login bounce.
 *
 * Route `_permission` still runs. When it denies uid 0, Drupal (and common
 * 403-to-login converters) emit `302 Location: /user/login`. Connector
 * verify follows that redirect; login HTML is 200; `principal_auth` fails.
 * This subscriber replaces that deny with the same authorization refusal the
 * controller returns for a hostile grant, so fetch sees 403 JSON.
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
    // converters, so this route never becomes Location /user/login.
    return [
      KernelEvents::EXCEPTION => ['onException', 100],
    ];
  }

  /**
   * Replaces an anonymous readiness AccessDenied with 403 JSON.
   *
   * @param \Symfony\Component\HttpKernel\Event\ExceptionEvent $event
   *   The exception event.
   */
  public function onException(ExceptionEvent $event): void {
    $exception = $event->getThrowable();
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

    $event->setResponse(new JsonResponse([
      'error' => 'MCP access is denied.',
      'reason' => McpGovernanceReadinessReason::Unauthenticated->value,
    ], 403, [
      'Cache-Control' => 'private, no-store',
      'X-Content-Type-Options' => 'nosniff',
    ]));
    $event->stopPropagation();
  }

}