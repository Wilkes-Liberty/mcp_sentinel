<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Controller\ControllerBase;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpRateLimiter;
use Drupal\mcp_sentinel\Service\McpSiteSchemaBuilder;
use Drupal\mcp_sentinel\Service\McpWhoamiRecorder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Serves the /drupal-mcp/context endpoint with full site schema.
 *
 * Returns content type fields (with labels), vocabularies, and media types —
 * richer than standard JSON:API discovery. Requires the 'access mcp sentinel
 * context' permission.
 */
class McpContextController extends ControllerBase {

  /**
   * Constructs an McpContextController.
   *
   * @param \Drupal\mcp_sentinel\Service\McpSiteSchemaBuilder $schemaBuilder
   *   Shared site-schema builder (content types, vocabularies, media types).
   * @param \Drupal\mcp_sentinel\Service\McpAccessChecker $accessChecker
   *   The access checker (evaluates the profile's IP allowlist).
   * @param \Drupal\mcp_sentinel\Service\McpGovernanceReadiness $readiness
   *   Source-governance readiness evaluator.
   * @param \Drupal\mcp_sentinel\Service\McpRateLimiter $rateLimiter
   *   Per-principal request-budget enforcement (finite by default).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Audit logger for bounded budget-denial evidence rows.
   * @param \Drupal\mcp_sentinel\Service\McpClassificationResolver|null $classification
   *   Classification egress ceilings (d.o #3616540 part 2): the schema
   *   document has a label, and over-ceiling bundles are not described.
   *   NULL only in the deploy window before the container rebuilds.
   * @param \Drupal\mcp_sentinel\Service\McpWhoamiRecorder|null $whoamiRecorder
   *   Last whoami recorder. NULL only in the deploy window.
   * @param \Drupal\mcp_sentinel\Service\McpDenyExplainer|null $denyExplainer
   *   Deny-path explainer. NULL only in the deploy window.
   */
  public function __construct(
    private readonly McpSiteSchemaBuilder $schemaBuilder,
    private readonly McpAccessChecker $accessChecker,
    private readonly McpGovernanceReadiness $readiness,
    private readonly McpRateLimiter $rateLimiter,
    private readonly McpAuditLogger $auditLogger,
    private readonly ?McpClassificationResolver $classification = NULL,
    private readonly ?McpWhoamiRecorder $whoamiRecorder = NULL,
    private readonly ?McpDenyExplainer $denyExplainer = NULL,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.site_schema_builder'),
      $container->get('mcp_sentinel.access_checker'),
      $container->get('mcp_sentinel.governance_readiness'),
      $container->get('mcp_sentinel.rate_limiter'),
      $container->get('mcp_sentinel.audit_logger'),
      $container->has('mcp_sentinel.classification') ? $container->get('mcp_sentinel.classification') : NULL,
      $container->has('mcp_sentinel.whoami_recorder') ? $container->get('mcp_sentinel.whoami_recorder') : NULL,
      $container->has('mcp_sentinel.deny_explainer') ? $container->get('mcp_sentinel.deny_explainer') : NULL,
    );
  }

  /**
   * Returns the full site schema as JSON for an MCP agent.
   *
   * IP allowlist enforcement: when the requesting account is governed by a
   * policy profile that carries an IP restriction, and the client IP is not
   * in the allowlist, a 403 response is returned immediately before any
   * schema data is emitted. The response carries no-store / no-cache headers
   * so it cannot be served to a later request from a different IP.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   The schema document (200), or a 403 when MCP access is disabled or the
   *   client IP is not permitted by policy.
   */
  public function context(): JsonResponse {
    $readiness = $this->readiness->evaluate(
      McpGovernedSurface::Context,
      $this->currentUser(),
      'mcp_read',
    );
    $this->whoamiRecorder?->record($readiness, 'context');
    if (!$readiness->isReady()) {
      return $this->notReadyResponse($readiness->reason());
    }

    // IP allowlist gate — governed requests only.
    $profile = $readiness->profile();
    if ($profile !== NULL && !$this->accessChecker->isClientIpAllowed($profile)) {
      return new JsonResponse(
        ['error' => 'Source IP not permitted by MCP Sentinel policy.'],
        403,
        ['Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff'],
      );
    }

    // Attested bundle / emergency deny (d.o #3617702). The schema document
    // does not go through entity access, so the floor is applied here.
    if ($this->accessChecker->checkBundleFloor('view', AccessResult::neutral())->isForbidden()) {
      return new JsonResponse(
        ['error' => 'MCP access is denied (' . McpAccessChecker::BUNDLE_DENIAL_CODE . ').'],
        403,
        ['Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff'],
      );
    }

    // Request budget (#3616540): the schema document is a governed read and
    // consumes the same finite-by-default per-principal budget as every
    // other read path.
    if ($profile !== NULL) {
      $uid = (int) $this->currentUser()->id();
      // NULL is the profile-wide flood key shared with JSON:API and GraphQL.
      if (!$this->rateLimiter->check($profile, $uid, NULL)) {
        $this->auditLogger->log('read_budget_denied', [
          'surface' => 'context',
          'budget' => 'requests',
          'profile' => $profile->id(),
        ]);
        return new JsonResponse(
          ['error' => 'MCP Sentinel request budget exceeded (read_budget_exceeded). Retry after the current window.'],
          429,
          ['Cache-Control' => 'no-store', 'Retry-After' => '60'],
        );
      }
      $this->rateLimiter->register($profile, $uid, NULL);
    }

    // Classification egress ceiling (d.o #3616540 part 2): the schema
    // document is metadata with a label of its own; a profile whose context
    // ceiling sits below it may not receive it at all, and one at or above
    // it is not told about bundles classified higher than its ceiling.
    // The resolver is NULL only in the deploy window before the container
    // rebuilds; no ceiling is evaluated then, exactly the previous behaviour.
    $ceiling = ($profile === NULL || $this->classification === NULL)
      ? NULL
      : $this->classification->effectiveCeiling($profile, McpGovernedSurface::Context);
    if ($profile !== NULL && $this->classification?->schemaDenied($profile, McpGovernedSurface::Context, $ceiling)) {
      return $this->classification->refusalResponse();
    }
    $describes = fn (string $entityTypeId, string $bundle): bool => $this->classification === NULL
      || $this->classification->describesBundle($profile, McpGovernedSurface::Context, $ceiling, $entityTypeId, $bundle);

    $schema = $this->schemaBuilder->build($describes);
    return new JsonResponse([
      'site'          => $this->buildSiteInfo(),
      'content_types' => $schema['content_types'],
      'vocabularies'  => $schema['vocabularies'],
      'media_types'   => $schema['media_types'],
      'generated_at'  => date('c'),
    ], 200, [
      'Cache-Control'          => 'private, no-store',
      'X-Content-Type-Options' => 'nosniff',
    ]);
  }

  /**
   * Liveness/health probe for the MCP endpoint — no authentication required.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   200 with status "ok" when MCP access is enabled, 503 with status
   *   "disabled" when the master switch is off.
   */
  public function health(): JsonResponse {
    $enabled = $this->config('mcp_sentinel.settings')->get('enabled') ?? TRUE;
    return new JsonResponse(
      ['status' => $enabled ? 'ok' : 'disabled', 'module' => 'mcp_sentinel'],
      $enabled ? 200 : 503,
      ['Cache-Control' => 'no-store']
    );
  }

  /**
   * Reports source-governance contract availability to authenticated callers.
   *
   * Anonymous callers are refused even when `access mcp sentinel context` has
   * been granted to the anonymous role. A hostile grant must not open this
   * governed path. This endpoint deliberately does not claim effective policy
   * enforcement, verified audit evidence, or an overall-green security
   * posture.
   */
  public function readiness(): JsonResponse {
    // Product rule, stronger than the route permission: uid 0 never receives
    // the readiness document. Route _permission can be granted to anonymous.
    if (!$this->currentUser()->isAuthenticated()) {
      return $this->notReadyResponse(
        McpGovernanceReadinessReason::Unauthenticated,
      );
    }

    $result = $this->readiness->contractStatus();
    $this->whoamiRecorder?->record($result, 'readiness');
    return new JsonResponse([
      'contract_ready' => $result->isReady(),
      'reason' => $result->reason()?->value,
      'scope' => 'source_governance_contract',
      'claims' => [
        'policy_effectiveness' => FALSE,
        'evidence_chain_verified' => FALSE,
        'overall_posture' => FALSE,
      ],
    ], $result->isReady() ? 200 : 503, [
      'Cache-Control' => 'private, no-store',
      'X-Content-Type-Options' => 'nosniff',
    ]);
  }

  /**
   * Builds a stable, non-secret readiness denial response.
   */
  private function notReadyResponse(McpGovernanceReadinessReason $reason): JsonResponse {
    $status = $reason->isAuthorizationFailure() ? 403 : 503;
    $error = $status === 403 ? 'MCP access is denied.' : 'MCP source governance is not ready.';
    $payload = [
      'error' => $error,
      'reason' => $reason->value,
      'rule' => $reason->value,
      'rule_name' => 'source-governance contract',
      'widen_appropriate' => FALSE,
      'next_step' => $reason->nextStep(),
      'explain' => $reason->operatorMessage(),
    ];
    if ($this->denyExplainer !== NULL) {
      $explained = $this->denyExplainer->explain($reason->value);
      $payload['rule_name'] = $explained->ruleName;
      $payload['widen_appropriate'] = $explained->widenAppropriate;
    }
    return new JsonResponse($payload, $status, [
      'Cache-Control' => 'private, no-store',
      'X-Content-Type-Options' => 'nosniff',
    ]);
  }

  /**
   * Builds the basic site-identity block.
   *
   * @return array
   *   The site name and default langcode. The Drupal version is deliberately
   *   excluded (see inline note).
   */
  private function buildSiteInfo(): array {
    // Deliberately omit the Drupal version: agents do not need it, and
    // disclosing it aids version-specific attacks.
    return [
      'name'     => $this->config('system.site')->get('name'),
      'langcode' => $this->config('system.site')->get('langcode'),
    ];
  }

}
