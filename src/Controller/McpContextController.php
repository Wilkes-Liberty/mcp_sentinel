<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
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
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   The policy resolver (resolves the governing profile for the request).
   * @param \Drupal\mcp_sentinel\Service\McpAccessChecker $accessChecker
   *   The access checker (evaluates the profile's IP allowlist).
   */
  public function __construct(
    private readonly EntityFieldManagerInterface $entityFieldManager,
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpAccessChecker $accessChecker,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_field.manager'),
      $container->get('mcp_sentinel.policy_resolver'),
      $container->get('mcp_sentinel.access_checker'),
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
    $config = $this->config('mcp_sentinel.settings');
    if (!$config->get('enabled')) {
      return new JsonResponse(['error' => 'MCP access is disabled.'], 403);
    }

    // IP allowlist gate — governed requests only.
    $profile = $this->policyResolver->resolve();
    if ($profile !== NULL && !$this->accessChecker->isClientIpAllowed($profile)) {
      return new JsonResponse(
        ['error' => 'Source IP not permitted by MCP Sentinel policy.'],
        403,
        ['Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff'],
      );
    }

    return new JsonResponse([
      'site'          => $this->buildSiteInfo(),
      'content_types' => $this->buildContentTypeSchemas(),
      'vocabularies'  => $this->buildVocabularySchemas(),
      'media_types'   => $this->buildMediaTypeInfo(),
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
   * @return array
   *   Keyed by node-type machine name; each entry carries the type label,
   *   description, and a field map (label, type, required, multiple). Internal
   *   base fields with no agent value are skipped.
   */
  private function buildContentTypeSchemas(): array {
    $skip   = ['vid', 'langcode', 'default_langcode', 'revision_translation_affected'];
    $types  = $this->entityTypeManager()->getStorage('node_type')->loadMultiple();
    $result = [];
    foreach ($types as $typeId => $type) {
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
   * @return array
   *   Keyed by vocabulary ID; each entry carries the label, description, and
   *   current term count (access checks bypassed for an accurate total).
   */
  private function buildVocabularySchemas(): array {
    $vocabs = $this->entityTypeManager()->getStorage('taxonomy_vocabulary')->loadMultiple();
    $result = [];
    foreach ($vocabs as $vid => $vocab) {
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
   * @return array
   *   Keyed by media-type machine name (label + source plugin ID), or an empty
   *   array when the media module is not installed.
   */
  private function buildMediaTypeInfo(): array {
    if (!$this->moduleHandler()->moduleExists('media')) {
      return [];
    }
    $result = [];
    foreach ($this->entityTypeManager()->getStorage('media_type')->loadMultiple() as $typeId => $type) {
      $result[$typeId] = [
        'label'  => (string) $type->label(),
        'source' => $type->getSource()->getPluginId(),
      ];
    }
    return $result;
  }

}
