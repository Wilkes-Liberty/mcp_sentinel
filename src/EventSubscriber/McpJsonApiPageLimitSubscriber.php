<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpRateLimiter;
use Drupal\mcp_sentinel\Service\McpReadBudgetResolver;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Governs JSON:API and GraphQL requests: IP allowlist, budgets, result caps.
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
 *    requested page[limit] exceeds the effective (finite-by-default) cap, an
 *    absent page[limit] is pinned to a cap smaller than JSON:API's default
 *    page size, and per-principal request and collection-page budgets bound
 *    chained calls and pagination amplification (#3616540).
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
   * @param \Drupal\mcp_sentinel\Service\McpRateLimiter $rateLimiter
   *   Per-principal request-budget enforcement (finite by default).
   * @param \Drupal\mcp_sentinel\Service\McpReadBudgetResolver $budgets
   *   Effective read-budget resolution.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Audit logger for bounded budget-denial evidence rows.
   */
  public function __construct(
    private readonly McpAccessChecker $accessChecker,
    private readonly McpGovernanceReadiness $readiness,
    private readonly AccountProxyInterface $currentUser,
    private readonly McpRateLimiter $rateLimiter,
    private readonly McpReadBudgetResolver $budgets,
    private readonly McpAuditLogger $auditLogger,
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
    $surface = McpGovernedSurface::fromPath($request->getPathInfo());
    if ($surface === NULL) {
      return;
    }

    // GraphQL reads travel over POST; the verb cannot select the scope there
    // (#3616540). The JSON:API surface keeps the verb-derived scope.
    $requiredScope = $surface === McpGovernedSurface::Graphql
      || in_array($request->getMethod(), ['GET', 'HEAD'], TRUE)
      ? 'mcp_read'
      : 'mcp_write';
    $readiness = $this->readiness->evaluate(
      $surface,
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

    // Request budget (#3616540): every governed JSON:API request counts
    // against the finite-by-default per-principal request budget. This is the
    // source-side chained-action floor — pagination loops, retries, and
    // follow-on calls all consume it.
    $uid = (int) $this->currentUser->id();
    if (!$this->rateLimiter->check($profile, $uid, NULL)) {
      $this->auditLogger->log('read_budget_denied', [
        'surface' => $surface->value,
        'budget' => 'requests',
        'profile' => $profile->id(),
        'path' => $request->getPathInfo(),
      ]);
      throw new TooManyRequestsHttpException(NULL,
        'MCP Sentinel request budget exceeded for the active profile (read_budget_exceeded). Retry after the current window.'
      );
    }
    $this->rateLimiter->register($profile, $uid, NULL);

    if ($surface !== McpGovernedSurface::JsonApi) {
      // The GraphQL surface shares only the request budget at this seam; row
      // bounding happens in the graphql submodule's result pass and byte
      // bounding in the response subscriber.
      return;
    }

    // Page budget (#3616540): collection reads count against a windowed
    // per-principal page budget so pagination cannot amplify a bounded
    // per-request cap into an unbounded export.
    if (in_array($request->getMethod(), ['GET', 'HEAD'], TRUE)
      && $this->isCollectionRequest($request)) {
      if (!$this->rateLimiter->checkPageBudget($profile, $uid)) {
        $this->auditLogger->log('read_budget_denied', [
          'surface' => 'jsonapi',
          'budget' => 'pages',
          'profile' => $profile->id(),
          'path' => $request->getPathInfo(),
        ]);
        throw new TooManyRequestsHttpException(NULL,
          'MCP Sentinel collection page budget exceeded for the active profile (page_budget_exceeded). Retry after the current window.'
        );
      }
      $this->rateLimiter->registerPageBudget($profile, $uid);
    }

    $cap = $this->budgets->effectiveResultCap($profile);
    if ($cap <= 0) {
      return;
    }

    // JSON:API uses page[limit] (nested in the 'page' query param array).
    $page = $request->query->all('page');
    if (!isset($page['limit'])) {
      // JSON:API's own default page size is 50. A finite cap below that must
      // bind the default page too, so the absent limit is pinned to the cap —
      // otherwise omitting page[limit] would read more rows than requesting
      // the maximum the policy allows.
      if ($cap < 50) {
        $page['limit'] = $cap;
        $request->query->set('page', $page);
      }
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
   * Returns TRUE when the request reads a JSON:API collection (a list page).
   *
   * Individual resources and their sub-paths end in (or contain) a UUID;
   * collection URLs end at the resource-type segment. Related/relationship
   * reads of a single resource are deliberately not counted as pages.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The incoming request.
   */
  private function isCollectionRequest(Request $request): bool {
    $path = rtrim($request->getPathInfo(), '/');
    return preg_match(
      '@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@i',
      $path,
    ) !== 1;
  }

}
