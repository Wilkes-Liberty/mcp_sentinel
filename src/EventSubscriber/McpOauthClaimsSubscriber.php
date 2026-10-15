<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Authentication\McpValidatedBearerClaimsInterface;
use Drupal\mcp_sentinel\Service\McpVerifiedOauthClaims;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\simple_oauth\Authentication\TokenAuthUserInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Stamps mcp_sentinel.token_claims from a resource-server-validated bearer.
 *
 * Runs after authentication and before the principal-context seal. An
 * attribute already set by another provider is left alone. A bearer the
 * resource server rejected is not parsed, and a Drupal user id is not
 * written as the subject.
 */
final class McpOauthClaimsSubscriber implements EventSubscriberInterface {

  public function __construct(
    private readonly AccountProxyInterface $currentUser,
    private readonly McpValidatedBearerClaimsInterface $claims,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Authentication is 300. The principal seal is 30.
    return [
      KernelEvents::REQUEST => ['onRequest', 250],
    ];
  }

  /**
   * Writes verified claims onto the main request.
   */
  public function onRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $request = $event->getRequest();
    if ($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)) {
      return;
    }
    $account = $this->currentUser->getAccount();
    if (!$account instanceof TokenAuthUserInterface) {
      return;
    }
    $payload = $this->claims->validatedClaims($request);
    if ($payload === NULL) {
      return;
    }
    $attribute = McpVerifiedOauthClaims::attributeFor($payload, (string) $account->id());
    if ($attribute === NULL) {
      return;
    }
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $attribute);
  }

}
