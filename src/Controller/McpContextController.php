<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityFieldManagerInterface;
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

  public function __construct(
    private readonly EntityFieldManagerInterface $entityFieldManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('entity_field.manager'),
    );
  }

  /**
   * Returns full site schema.
   */
  public function context(): JsonResponse {
    $config = $this->config('mcp_sentinel.settings');
    if (!$config->get('enabled')) {
      return new JsonResponse(['error' => 'MCP access is disabled.'], 403);
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
   * Health check — no auth required.
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
   * Builds basic site information.
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
   * Builds the content type field schemas.
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
   * Builds the vocabulary schemas.
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
   * Builds the media type information.
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
