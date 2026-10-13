<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Builds the frozen principal + tenant context at the request boundary.
 *
 * Runs after Drupal authentication so Paladin / sealed-token claims are
 * already on the request. Tools still go through the dispatcher; this
 * subscriber seals the immutable context once per request. The request
 * attribute is informational; tools read the holder.
 */
final class McpPrincipalContextSubscriber implements EventSubscriberInterface {

  /**
   * Constructs the subscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory $factory
   *   Token-derived context factory.
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Write-once sealed context.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
    private readonly McpPrincipalContextHolder $holder,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // After authentication (~300) so validated claims are present.
    return [
      KernelEvents::REQUEST => ['onRequest', 30],
    ];
  }

  /**
   * Seals the frozen context for the main request.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
   */
  public function onRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $request = $event->getRequest();
    $ctx = $this->factory->fromRequest($request);
    $this->holder->seal($ctx, $request);
    $request->attributes->set(McpPrincipalContext::REQUEST_ATTRIBUTE, $ctx);
  }

}
