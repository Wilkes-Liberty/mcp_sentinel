<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;

/**
 * Builds the shared site-schema document for HTTP context and the tool.
 *
 * Callers supply the per-surface bundle filter so Context and Tool keep
 * their own egress ceilings. Content types and vocabularies include
 * description so both surfaces emit the same payload.
 */
final class McpSiteSchemaBuilder {

  /**
   * Internal base fields with no agent value.
   */
  private const SKIP_FIELDS = [
    'vid',
    'langcode',
    'default_langcode',
    'revision_translation_affected',
  ];

  /**
   * Field types whose allowed_formats setting is a write restriction.
   */
  private const FORMATTED_FIELD_TYPES = [
    'text',
    'text_long',
    'text_with_summary',
  ];

  /**
   * Constructs an McpSiteSchemaBuilder.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entityFieldManager
   *   The entity field manager (reads content-type field definitions).
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler (gates media types when media is not installed).
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly EntityFieldManagerInterface $entityFieldManager,
    private readonly ModuleHandlerInterface $moduleHandler,
  ) {}

  /**
   * Builds the shared schema sections.
   *
   * @param callable $describes
   *   Filter (entity type ID, bundle) => bool: FALSE omits the bundle.
   *
   * @return array
   *   Keys content_types, vocabularies, and media_types. Content types
   *   carry label, description, and fields; vocabularies carry label,
   *   description, and term_count.
   */
  public function build(callable $describes): array {
    return [
      'content_types' => $this->buildContentTypeSchemas($describes),
      'vocabularies' => $this->buildVocabularySchemas($describes),
      'media_types' => $this->buildMediaTypeInfo($describes),
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
   *   description, and a field map (label, type, required, multiple).
   *   Text fields also carry allowed_formats: a list of format IDs, or an
   *   empty list when the field does not restrict formats.
   */
  private function buildContentTypeSchemas(callable $describes): array {
    $types = $this->entityTypeManager->getStorage('node_type')->loadMultiple();
    $result = [];
    foreach ($types as $typeId => $type) {
      if (!$describes('node', (string) $typeId)) {
        continue;
      }
      $fields = $this->entityFieldManager->getFieldDefinitions('node', $typeId);
      $fieldSchemas = [];
      foreach ($fields as $fieldName => $field) {
        if (in_array($fieldName, self::SKIP_FIELDS, TRUE)) {
          continue;
        }
        $row = [
          'label' => (string) $field->getLabel(),
          'type' => $field->getType(),
          'required' => $field->isRequired(),
          'multiple' => $field->getFieldStorageDefinition()->isMultiple(),
        ];
        if (in_array($field->getType(), self::FORMATTED_FIELD_TYPES, TRUE)) {
          $row['allowed_formats'] = $this->normalizeAllowedFormats(
            $field->getSetting('allowed_formats')
          );
        }
        $fieldSchemas[$fieldName] = $row;
      }
      $result[$typeId] = [
        'label' => (string) $type->label(),
        'description' => (string) $type->getDescription(),
        'fields' => $fieldSchemas,
      ];
    }
    return $result;
  }

  /**
   * Normalizes a text field's allowed_formats setting.
   *
   * Saved config is a sequence of format IDs. A checkbox map may still
   * carry 0 or "0" for a format that was not selected. An empty list means
   * the field does not restrict formats.
   *
   * @param mixed $raw
   *   The field setting.
   *
   * @return list<string>
   *   Enabled format IDs.
   */
  private function normalizeAllowedFormats(mixed $raw): array {
    if (!is_array($raw)) {
      return [];
    }
    $formats = [];
    foreach ($raw as $value) {
      if (!is_string($value) || $value === '' || $value === '0') {
        continue;
      }
      $formats[] = $value;
    }
    return $formats;
  }

  /**
   * Builds the taxonomy vocabulary schemas.
   *
   * @param callable $describes
   *   Filter (entity type ID, bundle) => bool: FALSE omits the bundle.
   *
   * @return array
   *   Keyed by vocabulary ID; each entry carries the label, description,
   *   and current term count (access checks bypassed for an accurate total).
   */
  private function buildVocabularySchemas(callable $describes): array {
    $vocabs = $this->entityTypeManager
      ->getStorage('taxonomy_vocabulary')
      ->loadMultiple();
    $result = [];
    foreach ($vocabs as $vid => $vocab) {
      if (!$describes('taxonomy_term', (string) $vid)) {
        continue;
      }
      $count = (int) $this->entityTypeManager
        ->getStorage('taxonomy_term')
        ->getQuery()
        ->accessCheck(FALSE)
        ->condition('vid', $vid)
        ->count()
        ->execute();
      $result[$vid] = [
        'label' => (string) $vocab->label(),
        'description' => (string) $vocab->getDescription(),
        'term_count' => $count,
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
   *   Keyed by media-type machine name (label + source plugin ID), or an
   *   empty array when the media module is not installed.
   */
  private function buildMediaTypeInfo(callable $describes): array {
    if (!$this->moduleHandler->moduleExists('media')) {
      return [];
    }
    $result = [];
    $mediaTypes = $this->entityTypeManager
      ->getStorage('media_type')
      ->loadMultiple();
    foreach ($mediaTypes as $typeId => $type) {
      if (!$describes('media', (string) $typeId)) {
        continue;
      }
      $result[$typeId] = [
        'label' => (string) $type->label(),
        'source' => $type->getSource()->getPluginId(),
      ];
    }
    return $result;
  }

}
