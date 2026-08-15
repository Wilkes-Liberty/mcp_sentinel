<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpRateLimiter;
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
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entityFieldManager
   *   The entity field manager (reads content-type field definitions).
   * @param \Drupal\mcp_sentinel\Service\McpAccessChecker $accessChecker
   *   The access checker (evaluates the profile's IP allowlist).
   * @param \Drupal\mcp_sentinel\Service\McpGovernanceReadiness $readiness
   *   Source-governance readiness evaluator.
   * @param \Drupal\mcp_sentinel\Service\McpRateLimiter $rateLimiter
   *   Per-principal request-budget enforcement (finite by default).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Audit logger for bounded budget-denial evidence rows.
   * @param \Drupal\mcp_sentinel\Service\McpClassificationResolver $classification
   *   Classification egress ceilings (d.o #3616540 part 2): the schema
   *   document has a label, and over-ceiling bundles are not described.
   */
  public function __construct(
    private readonly EntityFieldManagerInterface $entityFieldManager,
    private readonly McpAccessChecker $accessChecker,
    private readonly McpGovernanceReadiness $readiness,
    private readonly McpRateLimiter $rateLimiter,
    private readonly McpAuditLogger $auditLogger,
    private readonly McpClassificationResolver $classification,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_field.manager'),
      $container->get('mcp_sentinel.access_checker'),
      $container->get('mcp_sentinel.governance_readiness'),
      $container->get('mcp_sentinel.rate_limiter'),
      $container->get('mcp_sentinel.audit_logger'),
      $container->get('mcp_sentinel.classification'),
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
    $ceiling = $profile === NULL ? NULL : $this->classification->effectiveCeiling($profile, McpGovernedSurface::Context);
    if ($profile !== NULL && $ceiling !== NULL) {
      $schemaLabel = $this->classification->schemaLabel();
      if ($this->classification->exceeds($schemaLabel, $ceiling)) {
        $this->classification->evidence($profile, McpGovernedSurface::Context, 'schema', '', '', $schemaLabel, $ceiling);
        return $this->classification->refusalResponse();
      }
    }
    $describes = fn (string $entityTypeId, string $bundle): bool => $this->describes($profile, $ceiling, $entityTypeId, $bundle);

    return new JsonResponse([
      'site'          => $this->buildSiteInfo(),
      'content_types' => $this->buildContentTypeSchemas($describes),
      'vocabularies'  => $this->buildVocabularySchemas($describes),
      'media_types'   => $this->buildMediaTypeInfo($describes),
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
   * This endpoint deliberately does not claim effective policy enforcement,
   * verified audit evidence, or an overall-green security posture.
   */
  public function readiness(): JsonResponse {
    $result = $this->readiness->contractStatus();
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
    return new JsonResponse([
      'error' => $status === 403 ? 'MCP access is denied.' : 'MCP source governance is not ready.',
      'reason' => $reason->value,
    ], $status, [
      'Cache-Control' => 'private, no-store',
      'X-Content-Type-Options' => 'nosniff',
    ]);
  }

  /**
   * Whether a bundle may be described to the requesting principal.
   *
   * Over-ceiling bundles are omitted from the schema document (evidence is
   * written once per bundle per request); with no profile or no ceiling
   * everything is described, exactly as before.
   */
  private function describes(?McpPolicyProfileInterface $profile, ?string $ceiling, string $entityTypeId, string $bundle): bool {
    if ($profile === NULL || $ceiling === NULL) {
      return TRUE;
    }
    $label = $this->classification->labelForEntityType($entityTypeId, $bundle);
    if (!$this->classification->exceeds($label, $ceiling)) {
      return TRUE;
    }
    $this->classification->evidence($profile, McpGovernedSurface::Context, $entityTypeId, $bundle, '', $label, $ceiling);
    return FALSE;
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

  /**
   * Builds the per-content-type field schemas.
   *
   * @param callable $describes
   *   Filter (entity type ID, bundle) => bool: FALSE omits the bundle.
   *
   * @return array
   *   Keyed by node-type machine name; each entry carries the type label,
   *   description, and a field map (label, type, required, multiple). Internal
   *   base fields with no agent value are skipped.
   */
  private function buildContentTypeSchemas(callable $describes): array {
    $skip   = ['vid', 'langcode', 'default_langcode', 'revision_translation_affected'];
    $types  = $this->entityTypeManager()->getStorage('node_type')->loadMultiple();
    $result = [];
    foreach ($types as $typeId => $type) {
      if (!$describes('node', (string) $typeId)) {
        continue;
      }
      $fields = $this->entityFieldManager->getFieldDefinitions('node', $typeId);
      $fieldSchemas = [];
      foreach ($fields as $fieldName => $field) {
        if (in_array($fieldName, $skip, TRUE)) {
          continue;
        }
        $fieldSchemas[$fieldName] = [
          'label'    => (string) $field->getLabel(),
          'type'     => $field->getType(),
          'required' => $field->isRequired(),
          'multiple' => $field->getFieldStorageDefinition()->isMultiple(),
        ];
      }
      $result[$typeId] = [
        'label'       => (string) $type->label(),
        'description' => (string) $type->getDescription(),
        'fields'      => $fieldSchemas,
      ];
    }
    return $result;
  }

  /**
   * Builds the taxonomy vocabulary schemas.
   *
   * @param callable $describes
   *   Filter (entity type ID, bundle) => bool: FALSE omits the bundle.
   *
   * @return array
   *   Keyed by vocabulary ID; each entry carries the label, description, and
   *   current term count (access checks bypassed for an accurate total).
   */
  private function buildVocabularySchemas(callable $describes): array {
    $vocabs = $this->entityTypeManager()->getStorage('taxonomy_vocabulary')->loadMultiple();
    $result = [];
    foreach ($vocabs as $vid => $vocab) {
      if (!$describes('taxonomy_term', (string) $vid)) {
        continue;
      }
      $count = (int) $this->entityTypeManager()->getStorage('taxonomy_term')
        ->getQuery()->accessCheck(FALSE)->condition('vid', $vid)->count()->execute();
      $result[$vid] = [
        'label'       => (string) $vocab->label(),
        'description' => (string) $vocab->getDescription(),
        'term_count'  => $count,
      ];
    }
    return $result;
  }

  /**
   * Builds the media-type information.
   *
   * @param callable $describes
   *   Filter (entity type ID, bundle) => bool: FALSE omits the bundle.
   *
   * @return array
   *   Keyed by media-type machine name (label + source plugin ID), or an empty
   *   array when the media module is not installed.
   */
  private function buildMediaTypeInfo(callable $describes): array {
    if (!$this->moduleHandler()->moduleExists('media')) {
      return [];
    }
    $result = [];
    foreach ($this->entityTypeManager()->getStorage('media_type')->loadMultiple() as $typeId => $type) {
      if (!$describes('media', (string) $typeId)) {
        continue;
      }
      $result[$typeId] = [
        'label'  => (string) $type->label(),
        'source' => $type->getSource()->getPluginId(),
      ];
    }
    return $result;
  }

}
