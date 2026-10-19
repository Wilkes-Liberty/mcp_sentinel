<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
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
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface|null $authExtension
   *   Test-module hook
   *   (`mcp_sentinel_test.principal_auth_extension`). NULL
   *   unless that module owns the id.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
    private readonly McpPrincipalContextHolder $holder,
    private readonly ?McpPrincipalAuthExtensionInterface $authExtension = NULL,
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
    if ($this->isClaimlessUnsealed($request)
      && $this->authExtension?->deferClaimlessSeal($request) === TRUE) {
      return;
    }
    if ($this->isLeftoverCliRequest($request)) {
      return;
    }
    $ctx = $this->factory->fromRequest($request);
    try {
      $this->holder->seal($ctx, $request);
    }
    catch (McpPrincipalContextDeniedException $e) {
      if ($e->reasonCode !== McpPrincipalContextDeniedException::RESEAL_REFUSED) {
        throw $e;
      }
      $sealed = $this->holder->get();
      if ($sealed instanceof McpPrincipalContext) {
        $ctx = $sealed;
      }
    }
    $request->attributes->set(McpPrincipalContext::REQUEST_ATTRIBUTE, $ctx);
  }

  /**
   * Claimless, unsealed, non-network, non-fixture request.
   *
   * Production evaluates this before consulting the test hook.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   */
  private function isClaimlessUnsealed(Request $request): bool {
    return !$request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)
      && !$request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE)
      && $request->attributes->get(McpPrincipalContext::NETWORK_ATTRIBUTE) !== TRUE
      && $request->attributes->get(McpPrincipalContext::FIXTURE_ATTRIBUTE) !== TRUE;
  }

  /**
   * Drupal Drush/queue leftover: not an inbound Paladin HTTP call.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return bool
   *   TRUE when this is a claimless CLI bootstrap request.
   */
  private function isLeftoverCliRequest(Request $request): bool {
    if (PHP_SAPI !== 'cli') {
      return FALSE;
    }
    return !$request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)
      && !$request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE)
      && $request->attributes->get(McpPrincipalContext::NETWORK_ATTRIBUTE) !== TRUE;
  }

}
