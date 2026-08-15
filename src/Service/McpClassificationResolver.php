<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Site\Settings;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Resolves classification labels and per-surface egress ceilings.
 *
 * The source-side half of P4.8 (d.o #3616540 part 2). Two things are
 * configuration, not content inspection:
 *
 *  - Assignment (global, mcp_sentinel.settings:classification_map): facts
 *    about data. Rows label an entity type, optionally one bundle, optionally
 *    one field. Unlabelled data carries the lowest label of the site's
 *    ordered vocabulary (classification_labels), so an empty map labels
 *    nothing above the floor.
 *  - Ceilings (per profile, egress_ceilings): policy about principals. A
 *    "destination" is the pair (server-resolved profile, governed surface),
 *    and the ceiling is the highest label that pair may receive.
 *
 * Deny more, never less: a label outside the vocabulary counts as *above*
 * the highest label when it describes data and as the *lowest* label when it
 * names a ceiling. Hard P0.4 denies (entity-type deny lists, redacted
 * fields) are evaluated before any ceiling and always win.
 */
final class McpClassificationResolver {

  /**
   * The vocabulary used when a site has not named its own.
   */
  public const DEFAULT_LABELS = ['public', 'internal', 'restricted'];

  /**
   * The stable structured code carried by every classification refusal.
   */
  public const DENIAL_CODE = 'classification_egress_denied';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly RequestStack $requestStack,
    private readonly Settings $settings,
    private readonly McpAuditLogger $auditLogger,
  ) {}

  /**
   * The ordered vocabulary, lowest label first.
   *
   * @return string[]
   *   Non-empty, de-duplicated labels; the built-in default when the site has
   *   configured none.
   */
  public function labels(): array {
    $configured = $this->configFactory->get('mcp_sentinel.settings')->get('classification_labels');
    $labels = [];
    foreach (is_array($configured) ? $configured : [] as $label) {
      if (!is_string($label)) {
        continue;
      }
      $label = trim($label);
      if ($label !== '' && !in_array($label, $labels, TRUE)) {
        $labels[] = $label;
      }
    }
    return $labels === [] ? self::DEFAULT_LABELS : $labels;
  }

  /**
   * The lowest label — what unlabelled data carries.
   */
  public function lowestLabel(): string {
    return $this->labels()[0];
  }

  /**
   * The highest label in the vocabulary.
   */
  public function highestLabel(): string {
    $labels = $this->labels();
    return $labels[count($labels) - 1];
  }

  /**
   * The position of a label in the vocabulary, or NULL when it has none.
   */
  public function rank(string $label): ?int {
    $rank = array_search($label, $this->labels(), TRUE);
    return $rank === FALSE ? NULL : $rank;
  }

  /**
   * Whether data labelled $label may not leave through a ceiling of $ceiling.
   *
   * @param string $label
   *   The data's label. Unknown labels sit above the highest label.
   * @param string|null $ceiling
   *   The effective ceiling, or NULL for no ceiling. Unknown ceilings behave
   *   as the lowest label.
   */
  public function exceeds(string $label, ?string $ceiling): bool {
    if ($ceiling === NULL) {
      return FALSE;
    }
    $dataRank = $this->rank($label) ?? PHP_INT_MAX;
    $ceilingRank = $this->rank($ceiling) ?? 0;
    return $dataRank > $ceilingRank;
  }

  /**
   * The label assigned to an entity type, or one bundle of it.
   *
   * A bundle row beats a type row; nothing assigned means the lowest label.
   */
  public function labelForEntityType(string $entityTypeId, ?string $bundle = NULL): string {
    $rows = $this->rows();
    if ($bundle !== NULL && $bundle !== '') {
      $label = $rows[$entityTypeId][$bundle][''] ?? NULL;
      if ($label !== NULL) {
        return $label;
      }
    }
    return $rows[$entityTypeId][''][''] ?? $this->lowestLabel();
  }

  /**
   * The label assigned to one field, falling back to its entity's label.
   *
   * A bundle-scoped field row beats an any-bundle field row, which beats the
   * entity's own (bundle or type) label.
   */
  public function labelForField(string $entityTypeId, ?string $bundle, string $fieldName): string {
    $rows = $this->rows();
    if ($bundle !== NULL && $bundle !== '') {
      $label = $rows[$entityTypeId][$bundle][$fieldName] ?? NULL;
      if ($label !== NULL) {
        return $label;
      }
    }
    return $rows[$entityTypeId][''][$fieldName] ?? $this->labelForEntityType($entityTypeId, $bundle);
  }

  /**
   * The label of a concrete entity (its bundle row, else its type row).
   */
  public function labelForEntity(EntityInterface $entity): string {
    return $this->labelForEntityType($entity->getEntityTypeId(), $entity->bundle());
  }

  /**
   * The highest label any row assigns within an entity type.
   *
   * For seams that cannot see bundles — raw SQL over a type's tables, JSON:API
   * filter access — the whole type is judged by its most sensitive row.
   */
  public function highestLabelForEntityType(string $entityTypeId): string {
    $highest = $this->lowestLabel();
    $highestRank = 0;
    foreach ($this->rows()[$entityTypeId] ?? [] as $fields) {
      foreach ($fields as $label) {
        $rank = $this->rank($label) ?? PHP_INT_MAX;
        if ($rank > $highestRank) {
          $highestRank = $rank;
          $highest = $label;
        }
      }
    }
    return $highest;
  }

  /**
   * Whether the site has labelled anything above the lowest label.
   *
   * The half of the status-report question that concerns data: a site that
   * assigns nothing above the floor has no classification to enforce.
   */
  public function assignsAboveLowest(): bool {
    foreach ($this->rows() as $bundles) {
      foreach ($bundles as $fields) {
        foreach ($fields as $label) {
          if (($this->rank($label) ?? PHP_INT_MAX) > 0) {
            return TRUE;
          }
        }
      }
    }
    return FALSE;
  }

  /**
   * The assignment rows indexed as [entity_type][bundle][field] => label.
   *
   * Bundle '' means every bundle; field '' means the entity itself. Rows
   * without an entity type or label are ignored — a malformed row must never
   * turn a read into an exception.
   *
   * @return array<string, array<string, array<string, string>>>
   *   The index.
   */
  private function rows(): array {
    $configured = $this->configFactory->get('mcp_sentinel.settings')->get('classification_map');
    $index = [];
    foreach (is_array($configured) ? $configured : [] as $row) {
      if (!is_array($row)) {
        continue;
      }
      $type = trim((string) ($row['entity_type'] ?? ''));
      $label = trim((string) ($row['label'] ?? ''));
      if ($type === '' || $label === '') {
        continue;
      }
      $bundle = trim((string) ($row['bundle'] ?? ''));
      $field = trim((string) ($row['field'] ?? ''));
      $index[$type][$bundle][$field] = $label;
    }
    return $index;
  }

}
