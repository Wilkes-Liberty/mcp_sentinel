<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityFieldManagerInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;

/**
 * Locates the published host(s) that pin a composite child's revision.
 *
 * A composite child (a paragraph, or anything declaring
 * `entity_revision_parent_type_field`) is rendered through an
 * `entity_reference_revisions` (ERR) field that pins a *specific* revision by
 * `target_revision_id`. When a published host's default revision pins the
 * child's current stored revision, editing that revision in place changes the
 * live render — an effective publish (GitHub #46). This service answers the two
 * questions the publish gate needs:
 *
 * - Is the child's stored revision pinned by any *published* host default
 *   revision? (If so, an in-place edit is publish-class and must be governed.)
 * - Is the pin cleanly *redirectable* — a single, un-nested, published,
 *   non-composite host — so the edit can be transparently landed as a host
 *   draft rather than denied?
 *
 * Detection is generic: it enumerates ERR fields site-wide and queries each
 * field's *default-revision* data, so a hit means the referrer's default
 * revision pins exactly this revision. No paragraph-specific parent fields are
 * assumed, and the module no-ops cleanly when neither Paragraphs nor
 * entity_reference_revisions is installed (the field map is simply empty).
 */
final class McpPinnedCompositeLocator {

  /**
   * Maximum composite nesting depth to walk before giving up.
   */
  private const MAX_DEPTH = 10;

  /**
   * Per-request cache of the ERR field map (entity_type => [field => info]).
   *
   * @var array<string, array<string, mixed>>|null
   */
  private ?array $errFieldMap = NULL;

  /**
   * Constructs the locator.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Loads referrer entities and runs default-revision queries.
   * @param \Drupal\Core\Entity\EntityFieldManagerInterface $entityFieldManager
   *   Enumerates entity_reference_revisions fields across the site.
   * @param \Drupal\mcp_sentinel\Service\McpModerationGate $moderationGate
   *   Identifies composite children while walking up the host chain.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly EntityFieldManagerInterface $entityFieldManager,
    private readonly McpModerationGate $moderationGate,
  ) {}

  /**
   * Analyses whether a child's revision is pinned by a published host.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $child
   *   The composite child being edited.
   * @param int|string $pinnedRevisionId
   *   The child's stored (pre-edit) revision id — the revision a host default
   *   revision may pin. Callers pass the revision loaded from storage, not the
   *   in-flight edited entity.
   *
   * @return array{pinned_by_published: bool, redirectable: bool, pins: list<array{host: \Drupal\Core\Entity\ContentEntityInterface, field: string, delta: int}>, reasons: list<string>}
   *   - pinned_by_published: an in-place edit would change live content.
   *   - redirectable: the pin is a single, un-nested, published, non-composite
   *     host whose draft can be synthesised safely.
   *   - pins: redirect descriptors (only when redirectable).
   *   - reasons: why a published pin is not redirectable (for audit).
   */
  public function analyze(ContentEntityInterface $child, int|string $pinnedRevisionId): array {
    $pinnedByPublished = FALSE;
    $redirectablePins = [];
    $reasons = [];

    foreach ($this->findDefaultRevisionReferrers($child->id(), $pinnedRevisionId) as $referrer) {
      [$host, $published] = $this->resolveTopHost($referrer['entity']);
      if ($host === NULL || !$published) {
        continue;
      }
      $pinnedByPublished = TRUE;

      // Cleanly redirectable only when the direct referrer *is* the published
      // top-level host (paragraph attached directly to a node), not a nested
      // intermediary. Nested chains need multi-level re-pinning, deferred.
      if ($referrer['entity']->getEntityTypeId() === $host->getEntityTypeId()
        && (string) $referrer['entity']->id() === (string) $host->id()) {
        $redirectablePins[] = [
          'host' => $host,
          'field' => $referrer['field'],
          'delta' => $referrer['delta'],
        ];
      }
      else {
        $reasons[] = 'nested';
      }
    }

    // Fan-out across multiple published hosts is deferred: one edit forking N
    // drafts is surprising and error-prone. Deny (never mutate in place).
    if (count($redirectablePins) > 1) {
      $reasons[] = 'multi_host';
      $redirectablePins = [];
    }

    $redirectable = $pinnedByPublished && $reasons === [] && $redirectablePins !== [];

    return [
      'pinned_by_published' => $pinnedByPublished,
      'redirectable' => $redirectable,
      'pins' => $redirectablePins,
      'reasons' => array_values(array_unique($reasons)),
    ];
  }

  /**
   * Finds entities whose default revision pins a given target revision.
   *
   * @param int|string|null $targetId
   *   The referenced (child) entity id.
   * @param int|string $targetRevisionId
   *   The specific referenced revision id (the pin).
   *
   * @return list<array{entity: \Drupal\Core\Entity\ContentEntityInterface, field: string, delta: int}>
   *   Referrer descriptors: the loaded default-revision entity, the ERR field
   *   name, and the delta at which it pins the target revision.
   */
  private function findDefaultRevisionReferrers(int|string|null $targetId, int|string $targetRevisionId): array {
    if ($targetId === NULL) {
      return [];
    }
    $referrers = [];
    foreach ($this->getErrFieldMap() as $entityTypeId => $fields) {
      $storage = $this->entityTypeManager->getStorage($entityTypeId);
      foreach (array_keys($fields) as $fieldName) {
        // Default-revision query (no ->allRevisions()): a hit means the
        // referrer's *default* revision pins this target revision.
        $ids = $storage->getQuery()
          ->accessCheck(FALSE)
          ->condition($fieldName . '.target_id', $targetId)
          ->condition($fieldName . '.target_revision_id', $targetRevisionId)
          ->execute();
        if (!$ids) {
          continue;
        }
        foreach ($storage->loadMultiple($ids) as $entity) {
          if (!$entity instanceof ContentEntityInterface || !$entity->hasField($fieldName)) {
            continue;
          }
          // loadUnchanged so an in-flight mutated static cache never masks the
          // stored pin we are matching against.
          $fresh = $storage->loadUnchanged($entity->id());
          if (!$fresh instanceof ContentEntityInterface) {
            continue;
          }
          foreach ($fresh->get($fieldName) as $delta => $item) {
            $value = $item->getValue();
            if (isset($value['target_id'], $value['target_revision_id'])
              && (string) $value['target_id'] === (string) $targetId
              && (string) $value['target_revision_id'] === (string) $targetRevisionId) {
              $referrers[] = [
                'entity' => $fresh,
                'field' => $fieldName,
                'delta' => (int) $delta,
              ];
            }
          }
        }
      }
    }
    return $referrers;
  }

  /**
   * Walks a referrer up to its top-level (non-composite) host.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $referrer
   *   The direct referrer of the edited child's revision.
   *
   * @return array{0: \Drupal\Core\Entity\ContentEntityInterface|null, 1: bool}
   *   The top-level host (or NULL when it cannot be resolved), and whether that
   *   host's default revision is published.
   */
  private function resolveTopHost(ContentEntityInterface $referrer): array {
    $current = $referrer;
    $depth = 0;
    while ($this->moderationGate->isCompositeChild($current) && $depth < self::MAX_DEPTH) {
      $depth++;
      $parents = $this->findDefaultRevisionReferrers($current->id(), $current->getRevisionId());
      if ($parents === []) {
        // Orphan composite: not pinned by any default revision → no live host.
        return [NULL, FALSE];
      }
      $current = $parents[0]['entity'];
    }
    if ($this->moderationGate->isCompositeChild($current)) {
      // Exceeded depth guard; treat as unresolved rather than risk a cycle.
      return [NULL, FALSE];
    }
    $published = $current instanceof EntityPublishedInterface && $current->isPublished();
    return [$current, $published];
  }

  /**
   * Returns the site-wide entity_reference_revisions field map, cached.
   *
   * @return array<string, array<string, mixed>>
   *   Map of entity_type_id => [field_name => field info].
   */
  private function getErrFieldMap(): array {
    if ($this->errFieldMap === NULL) {
      $this->errFieldMap = $this->entityFieldManager
        ->getFieldMapByFieldType('entity_reference_revisions');
    }
    return $this->errFieldMap;
  }

}
