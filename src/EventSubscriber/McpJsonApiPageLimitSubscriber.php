<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Governs JSON:API requests: IP allowlist + the profile result_count_cap.
 *
 * Drupal 11.3 core does not expose a hook_jsonapi_resource_params_alter hook.
 * This subscriber runs at KernelEvents::REQUEST priority -20 (after routing and
 * authentication but before the JSON:API controller parses pagination params),
 * so the database never reads excess rows for governed agents.
 *
 * Two governance gates fire here for governed (profile-resolved) JSON:API
 * traffic:
 * 1. IP allowlist — the request subscriber is the single seam that uniformly
 *    covers BOTH the collection endpoint (/jsonapi/node/article) and individual
 *    resources (/jsonapi/node/article/{uuid}) as well as writes. The individual
 *    and write paths are ALSO IP-gated by hook_entity_access (defence in
 *    depth); the collection (filter-access) path was NOT, so an agent from a
 *    disallowed IP could enumerate collections. Enforcing here closes that gap
 *    for every JSON:API shape at once. A 403 is returned when the client IP is
 *    not in the profile's non-empty allowed_ips list. An empty allowed_ips list
 *    imposes no restriction.
 * 2. result_count_cap on page[limit] — a 400 Bad Request is returned when the
 *    requested page[limit] exceeds the profile cap.
 *
 * Both gates only apply to requests that:
 * 1. Have a path containing '/jsonapi/' (covers both '/jsonapi/...' and
 *    language-prefixed paths like '/en/jsonapi/...')
 * 2. Are governed (policy resolver returns a non-NULL profile).
 */
final class McpJsonApiPageLimitSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an McpJsonApiPageLimitSubscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAccessChecker $accessChecker
   *   The MCP Sentinel access checker, used for the IP-allowlist gate.
   * @param \Drupal\mcp_sentinel\Service\McpGovernanceReadiness $readiness
   *   Source-governance readiness evaluator.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   Current authenticated account.
   */
  public function __construct(
    private readonly McpAccessChecker $accessChecker,
    private readonly McpGovernanceReadiness $readiness,
    private readonly AccountProxyInterface $currentUser,
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

    $requiredScope = in_array($request->getMethod(), ['GET', 'HEAD'], TRUE)
      ? 'mcp_read'
      : 'mcp_write';
    $readiness = $this->readiness->evaluate(
      McpGovernedSurface::JsonApi,
      $this->currentUser,
      $requiredScope,
    );
    if (!$readiness->isApplicable()) {
      return;
    }
    if (!$readiness->isReady()) {
      $reason = $readiness->reason();
      if ($reason?->isAuthorizationFailure()) {
        throw new AccessDeniedHttpException('MCP access is denied.');
      }
      throw new ServiceUnavailableHttpException(
        NULL,
        'MCP source governance is not ready: '
        . $reason->value . '.',
      );
    }

    $profile = $readiness->profile();
    if ($profile === NULL) {
      throw new ServiceUnavailableHttpException(
        NULL,
        'MCP source governance is not ready: active_profile_missing.',
      );
    }

    // IP allowlist: deny the whole JSON:API request (collection, individual or
    // write) when the client IP is not permitted. An empty allowed_ips list
    // imposes no restriction. Client IP is not a cache context, but the
    // JSON:API controller already varies/uncaches dynamic-page responses; this
    // 403 is an exception thrown before the controller runs, so no allowed
    // result can be re-served across IPs from this seam.
    if (!$this->accessChecker->isClientIpAllowed($profile)) {
      throw new AccessDeniedHttpException(
        'Source IP not permitted by MCP Sentinel policy.'
      );
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
