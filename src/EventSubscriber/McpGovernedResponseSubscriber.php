<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\jsonapi\ResourceType\ResourceTypeRepositoryInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpExfiltrationGuard;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
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
    private readonly ?McpClassificationResolver $classification = NULL,
    private readonly ?ResourceTypeRepositoryInterface $resourceTypes = NULL,
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

    // GraphQL travels over POST for queries and mutations; the HTTP seam
    // cannot see the operation type. Accept either GraphQL-relevant scope
    // so write-only mutation responses are still measured and read-only
    // query agents are not skipped. Operation scope is applied by
    // GraphqlGovernanceSubscriber. JSON:API keeps the verb-derived scope.
    $requiredScope = $surface === McpGovernedSurface::Graphql
      ? ['mcp_read', 'mcp_write']
      : (in_array($request->getMethod(), ['GET', 'HEAD'], TRUE)
        ? 'mcp_read'
        : 'mcp_write');
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
      // Within the byte budget: the classification seam (d.o #3616540 part
      // 2) is defense in depth behind entity and field access — an
      // over-ceiling resource type that survived to serialization is
      // refused with the same structured code the request seam uses.
      if ($surface === McpGovernedSurface::JsonApi
        && $this->classificationRefuses($event->getResponse(), $content, $profile)) {
        $event->setResponse($this->classification->refusalResponse());
      }
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

  /**
   * Whether a rendered JSON:API body carries an over-ceiling resource type.
   *
   * Applies to successful JSON:API documents only: errors carry no resources
   * and other content types are not this seam's business. Every `type` in
   * `data` and `included` is resolved to its entity type and bundle through
   * the resource type repository (alias-aware) and judged against the
   * profile's JSON:API ceiling. Deny more: a body that cannot be decoded, or
   * a type name the repository does not know, is refused while a ceiling is
   * in force — this seam guarantees no unmeasured payload leaves.
   *
   * @param \Symfony\Component\HttpFoundation\Response $response
   *   The rendered response.
   * @param string $content
   *   Its body.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved profile.
   *
   * @return bool
   *   TRUE when the body must be replaced with the classification refusal.
   */
  private function classificationRefuses(Response $response, string $content, McpPolicyProfileInterface $profile): bool {
    if ($this->classification === NULL || $this->resourceTypes === NULL) {
      return FALSE;
    }
    if (!$response->isSuccessful()
      || !str_contains((string) $response->headers->get('Content-Type', ''), 'application/vnd.api+json')
      || !$this->classification->assignsAboveLowest()) {
      return FALSE;
    }
    $surface = McpGovernedSurface::JsonApi;
    $ceiling = $this->classification->effectiveCeiling($profile, $surface);
    if ($ceiling === NULL) {
      return FALSE;
    }
    try {
      $document = json_decode($content, TRUE, 64, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      $document = NULL;
    }
    if (!is_array($document)) {
      $this->classification->evidence($profile, $surface, '(undecodable)', '', '', $this->classification->highestLabel(), $ceiling);
      return TRUE;
    }
    foreach ($this->resourceTypeNames($document) as $typeName) {
      $resourceType = $this->resourceTypes->getByTypeName($typeName);
      if ($resourceType === NULL) {
        // Not a resource type this site serves; nothing here can vouch for
        // it, so it is judged as the highest label.
        $this->classification->evidence($profile, $surface, substr($typeName, 0, 64), '', '', $this->classification->highestLabel(), $ceiling);
        return TRUE;
      }
      $label = $this->classification->labelForEntityType($resourceType->getEntityTypeId(), $resourceType->getBundle());
      if ($this->classification->exceeds($label, $ceiling)) {
        $this->classification->evidence($profile, $surface, $resourceType->getEntityTypeId(), $resourceType->getBundle(), '', $label, $ceiling);
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * The distinct resource type names in a JSON:API document's data + included.
   *
   * @param array $document
   *   The decoded document.
   *
   * @return string[]
   *   Type names, in first-seen order.
   */
  private function resourceTypeNames(array $document): array {
    $names = [];
    foreach (['data', 'included'] as $member) {
      $value = $document[$member] ?? NULL;
      if (!is_array($value)) {
        continue;
      }
      // A single resource object has a string 'type'; a list has objects.
      $objects = isset($value['type']) ? [$value] : $value;
      foreach ($objects as $object) {
        if (is_array($object) && is_string($object['type'] ?? NULL) && $object['type'] !== '') {
          $names[$object['type']] = TRUE;
        }
      }
    }
    return array_keys($names);
  }

}
