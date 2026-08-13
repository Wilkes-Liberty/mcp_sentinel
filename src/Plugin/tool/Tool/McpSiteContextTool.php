<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Returns the full site schema: content types, fields, vocabularies, media.
 *
 * Agents should call this before creating or editing content so they know the
 * available bundles and fields. Mirrors the /drupal-mcp/context endpoint.
 */
#[Tool(
  id: 'mcp_sentinel_site_context',
  label: new TranslatableMarkup('Get site schema context'),
  description: new TranslatableMarkup('Returns all content types with field labels and types, taxonomy vocabularies with term counts, and media types. Call this before creating or editing content to understand the available fields.'),
  operation: ToolOperation::Explain,
)]
final class McpSiteContextTool extends McpGovernedToolBase {

  /**
   * The entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The entity field manager.
   */
  protected EntityFieldManagerInterface $entityFieldManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->entityFieldManager = $container->get('entity_field.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $skip = ['vid', 'langcode', 'default_langcode', 'revision_translation_affected'];
    $data = ['content_types' => [], 'vocabularies' => [], 'media_types' => []];

    foreach ($this->entityTypeManager->getStorage('node_type')->loadMultiple() as $type_id => $type) {
      $field_schemas = [];
      foreach ($this->entityFieldManager->getFieldDefinitions('node', $type_id) as $name => $field) {
        if (in_array($name, $skip, TRUE)) {
          continue;
        }
        $field_schemas[$name] = [
          'label' => (string) $field->getLabel(),
          'type' => $field->getType(),
          'required' => $field->isRequired(),
          'multiple' => $field->getFieldStorageDefinition()->isMultiple(),
        ];
      }
      $data['content_types'][$type_id] = [
        'label' => (string) $type->label(),
        'fields' => $field_schemas,
      ];
    }

    foreach ($this->entityTypeManager->getStorage('taxonomy_vocabulary')->loadMultiple() as $vid => $vocab) {
      $count = (int) $this->entityTypeManager->getStorage('taxonomy_term')
        ->getQuery()->accessCheck(FALSE)->condition('vid', $vid)->count()->execute();
      $data['vocabularies'][$vid] = [
        'label' => (string) $vocab->label(),
        'term_count' => $count,
      ];
    }

    if ($this->entityTypeManager->hasDefinition('media_type')) {
      foreach ($this->entityTypeManager->getStorage('media_type')->loadMultiple() as $type_id => $type) {
        $data['media_types'][$type_id] = [
          'label' => (string) $type->label(),
          'source' => $type->getSource()->getPluginId(),
        ];
      }
    }

    return ExecutableResult::success($this->t('Site schema retrieved.'), $data);
  }

}
