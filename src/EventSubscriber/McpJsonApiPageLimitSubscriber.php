<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Enforces the profile result_count_cap on JSON:API page[limit] requests.
 *
 * Drupal 11.3 core does not expose a hook_jsonapi_resource_params_alter hook.
 * This subscriber runs at KernelEvents::REQUEST priority -20 (after routing and
 * authentication but before the JSON:API controller parses pagination params),
 * so the database never reads excess rows for governed agents.
 *
 * Enforcement only applies to requests that:
 * 1. Have a path containing '/jsonapi/' (covers both '/jsonapi/...' and
 *    language-prefixed paths like '/en/jsonapi/...')
 * 2. Are governed (policy resolver returns a non-NULL profile)
 * 3. Include a page[limit] parameter >= 1 that exceeds the cap (and cap > 0)
 *
 * A 400 Bad Request is returned to the agent with a descriptive message.
 */
final class McpJsonApiPageLimitSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an McpJsonApiPageLimitSubscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   The MCP Sentinel policy resolver.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      KernelEvents::REQUEST => [['onRequest', -20]],
    ];
  }

  /**
   * Checks and enforces the page[limit] cap for governed JSON:API requests.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
   *   When the requested page[limit] exceeds the profile cap.
   */
  public function onRequest(RequestEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $request = $event->getRequest();
    if (!$this->isJsonApiRequest($request)) {
      return;
    }

    $profile = $this->policyResolver->resolve();
    if ($profile === NULL) {
      return;
    }

    $cap = $profile->getResultCountCap();
    if ($cap <= 0) {
      return;
    }

    // JSON:API uses page[limit] (nested in the 'page' query param array).
    $page = $request->query->all('page');
    if (!isset($page['limit'])) {
      return;
    }

    $limit = (int) $page['limit'];
    // A zero, negative, or non-numeric value (cast to 0) is invalid on its own
    // terms — leave it for JSON:API's own parameter validation rather than
    // treating it as a cap violation.
    if ($limit < 1) {
      return;
    }
    if ($limit > $cap) {
      throw new BadRequestHttpException(
        sprintf(
          'Requested page[limit] %d exceeds the MCP Sentinel result cap of %d '
          . 'for the active profile. Reduce page[limit] or contact the site admin.',
          $limit,
          $cap,
        ),
      );
    }
  }

  /**
   * Returns TRUE when the request targets a JSON:API endpoint.
   *
   * Detects by the presence of the '/jsonapi/' segment anywhere in the path,
   * rather than as a strict prefix, so that language-prefixed URLs such as
   * '/en/jsonapi/node/article' (URL language negotiation) are also matched.
   * Routing attributes may not be populated at KernelEvents::REQUEST
   * priority -20, so path matching is the reliable detection strategy here.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   */
  private function isJsonApiRequest(Request $request): bool {
    return str_contains($request->getPathInfo(), '/jsonapi/');
  }

}
