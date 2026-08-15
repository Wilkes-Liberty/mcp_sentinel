<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
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
   * The policy resolver.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * Classification egress ceilings.
   */
  protected McpClassificationResolver $classification;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->entityFieldManager = $container->get('entity_field.manager');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->classification = $container->get('mcp_sentinel.classification');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    // Classification egress ceiling (d.o #3616540 part 2): this document is
    // the same schema the context endpoint serves, judged against the Tool
    // ceiling — refused below the schema label, and over-ceiling bundles are
    // not described.
    $profile = $this->policyResolver->resolve();
    $ceiling = $profile === NULL ? NULL : $this->classification->effectiveCeiling($profile, McpGovernedSurface::Tool);
    if ($profile !== NULL && $ceiling !== NULL) {
      $schema_label = $this->classification->schemaLabel();
      if ($this->classification->exceeds($schema_label, $ceiling)) {
        $this->classification->evidence($profile, McpGovernedSurface::Tool, 'schema', '', '', $schema_label, $ceiling);
        return ExecutableResult::failure($this->t("The site schema is classified above this principal's egress ceiling (@code).", [
          '@code' => McpClassificationResolver::DENIAL_CODE,
        ]));
      }
    }

    $skip = ['vid', 'langcode', 'default_langcode', 'revision_translation_affected'];
    $data = ['content_types' => [], 'vocabularies' => [], 'media_types' => []];

    foreach ($this->entityTypeManager->getStorage('node_type')->loadMultiple() as $type_id => $type) {
      if (!$this->describes($profile, $ceiling, 'node', (string) $type_id)) {
        continue;
      }
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
      if (!$this->describes($profile, $ceiling, 'taxonomy_term', (string) $vid)) {
        continue;
      }
      $count = (int) $this->entityTypeManager->getStorage('taxonomy_term')
        ->getQuery()->accessCheck(FALSE)->condition('vid', $vid)->count()->execute();
      $data['vocabularies'][$vid] = [
        'label' => (string) $vocab->label(),
        'term_count' => $count,
      ];
    }

    if ($this->entityTypeManager->hasDefinition('media_type')) {
      foreach ($this->entityTypeManager->getStorage('media_type')->loadMultiple() as $type_id => $type) {
        if (!$this->describes($profile, $ceiling, 'media', (string) $type_id)) {
          continue;
        }
        $data['media_types'][$type_id] = [
          'label' => (string) $type->label(),
          'source' => $type->getSource()->getPluginId(),
        ];
      }
    }

    return ExecutableResult::success($this->t('Site schema retrieved.'), $data);
  }

  /**
   * Whether a bundle may be described to the requesting principal.
   *
   * Mirrors the context endpoint: over-ceiling bundles are omitted (with one
   * evidence row per bundle per request); no profile or no ceiling describes
   * everything, exactly as before.
   */
  private function describes(?McpPolicyProfileInterface $profile, ?string $ceiling, string $entity_type_id, string $bundle): bool {
    if ($profile === NULL || $ceiling === NULL) {
      return TRUE;
    }
    $label = $this->classification->labelForEntityType($entity_type_id, $bundle);
    if (!$this->classification->exceeds($label, $ceiling)) {
      return TRUE;
    }
    $this->classification->evidence($profile, McpGovernedSurface::Tool, $entity_type_id, $bundle, '', $label, $ceiling);
    return FALSE;
  }

}
