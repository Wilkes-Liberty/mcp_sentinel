<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpExfiltrationGuard;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Enforces the response byte budget on governed JSON:API/GraphQL responses.
 *
 * The Tool bridge measures its serialized responses against the profile's
 * response-size cap, but JSON:API and GraphQL responses were never measured —
 * a governed agent could exfiltrate any volume in a single request on those
 * channels (#3616540). This subscriber measures the rendered response for
 * governed traffic on both paths and replaces an over-budget body with a
 * bounded 413 refusal carrying the stable reason code
 * `response_size_cap_exceeded`, plus a bounded, non-sensitive audit row.
 *
 * The refusal deliberately happens after rendering: the budget is an
 * egress control, not a query planner. Row-level bounding happens earlier
 * (result caps, page[limit] pinning); this seam is the backstop that
 * guarantees no governed channel can return an unmeasured payload.
 *
 * Ungoverned traffic — anonymous site visitors, ordinary editors — is never
 * measured or altered.
 */
final class McpGovernedResponseSubscriber implements EventSubscriberInterface {

  public function __construct(
    private readonly McpGovernanceReadiness $readiness,
    private readonly AccountProxyInterface $currentUser,
    private readonly McpExfiltrationGuard $guard,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Late enough that the body is final, early enough to run before
    // compression/streaming finish-response listeners.
    return [
      KernelEvents::RESPONSE => [['onResponse', -50]],
    ];
  }

  /**
   * Replaces an over-budget governed response with a bounded 413 refusal.
   *
   * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
   *   The response event.
   */
  public function onResponse(ResponseEvent $event): void {
    if (!$event->isMainRequest()) {
      return;
    }
    $request = $event->getRequest();
    $surface = McpGovernedSurface::fromPath($request->getPathInfo());
    if ($surface === NULL) {
      return;
    }

    // GraphQL reads travel over POST, so scope cannot be derived from the
    // HTTP verb there — a read-only principal's query would evaluate as a
    // write, fail readiness, and skip measurement entirely. Egress
    // measurement is a read-class control on every surface it covers.
    $requiredScope = $surface === McpGovernedSurface::Graphql
      || in_array($request->getMethod(), ['GET', 'HEAD'], TRUE)
      ? 'mcp_read'
      : 'mcp_write';
    $readiness = $this->readiness->evaluate($surface, $this->currentUser, $requiredScope);
    if (!$readiness->isApplicable() || !$readiness->isReady()) {
      // Ungoverned traffic is out of scope; a not-ready governed request was
      // already refused by the request-side gates.
      return;
    }
    $profile = $readiness->profile();
    if ($profile === NULL) {
      return;
    }

    $content = $event->getResponse()->getContent();
    if (!is_string($content) || $content === '') {
      // Streamed/binary responses expose no measurable string body here.
      return;
    }
    $bytes = strlen($content);
    if (!$this->guard->exceedsResponseSizeCap($bytes, $profile)) {
      return;
    }

    $cap = $this->guard->effectiveResponseSizeCap($profile);
    // Bounded, non-sensitive evidence: sizes and the path — never the payload.
    $this->auditLogger->log('read_budget_denied', [
      'surface' => $surface->value,
      'budget' => 'bytes',
      'profile' => $profile->id(),
      'path' => $request->getPathInfo(),
      'response_bytes' => $bytes,
      'cap' => $cap,
    ]);

    $refusal = new JsonResponse([
      'errors' => [
        [
          'status' => '413',
          'code' => 'response_size_cap_exceeded',
          'title' => 'Response exceeds the MCP Sentinel response-size budget',
          'detail' => sprintf(
            'The rendered response (%d bytes) exceeds the effective cap of %d bytes for the active profile. Narrow the query, request fewer fields, or lower page[limit].',
            $bytes,
            $cap,
          ),
        ],
      ],
    ], 413);
    // The refusal is per-principal state; it must never be cached or shared.
    $refusal->setPrivate();
    $refusal->headers->set('Cache-Control', 'private, no-store');
    $event->setResponse($refusal);
  }

}
