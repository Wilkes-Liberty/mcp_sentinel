<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Restores Cache-Control: private, no-store on the sealed-token reveal page.
 *
 * The reveal render array attaches that header. Core's
 * FinishResponseSubscriber then replaces Cache-Control on cacheable HTML,
 * including this admin page, with no-cache, must-revalidate. It does not
 * keep a header the controller already set. This listener runs after that
 * subscriber and restores private, no-store on the reveal routes only.
 */
final class McpSealedTokenRevealSubscriber implements EventSubscriberInterface {

  /**
   * Routes whose responses must not be stored (GET prompt and POST reveal).
   *
   * Both share the reveal path. The GET page says whether a secret is
   * waiting; the POST page carries the plaintext. Neither may be cached.
   */
  private const ROUTES = [
    McpSealedTokenRevealCsrfDenySubscriber::GET_ROUTE,
    McpSealedTokenRevealCsrfDenySubscriber::ROUTE,
  ];

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // FinishResponseSubscriber::onRespond is priority 0. The governed
    // response subscriber is -50 and does not touch these admin routes.
    return [
      KernelEvents::RESPONSE => ['onResponse', -20],
    ];
  }

  /**
   * Sets Cache-Control: private, no-store on the reveal routes.
   *
   * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
   *   The response event.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $route = $event->getRequest()->attributes->get('_route');
    // Only the prompt and the consume response get private, no-store.
    if (!in_array($route, self::ROUTES, TRUE)) {
      return;
    }
    $event->getResponse()->headers->set('Cache-Control', 'private, no-store');
  }

}
