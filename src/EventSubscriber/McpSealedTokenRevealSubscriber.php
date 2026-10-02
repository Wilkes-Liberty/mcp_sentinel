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
 * subscriber and restores private, no-store on the reveal route only.
 */
final class McpSealedTokenRevealSubscriber implements EventSubscriberInterface {

  /**
   * Route whose response must not be stored.
   */
  private const ROUTE = 'mcp_sentinel.sealed_token_reveal';

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // FinishResponseSubscriber::onRespond is priority 0. The governed
    // response subscriber is -50 and does not touch this admin route.
    return [
      KernelEvents::RESPONSE => ['onResponse', -20],
    ];
  }

  /**
   * Sets Cache-Control: private, no-store on the reveal route.
   *
   * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
   *   The response event.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    if ($event->getRequest()->attributes->get('_route') !== self::ROUTE) {
      return;
    }
    $event->getResponse()->headers->set('Cache-Control', 'private, no-store');
  }

}
