<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Draft;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

/**
 * One validated nested replacement, applied inside the draft transaction.
 *
 * Planning builds the new paragraphs and the snapshots. Applying only
 * attaches the new parent to the draft. After the draft save, published
 * paragraphs that Entity Reference Revisions rewrote in place are restored
 * or the transaction is failed.
 */
final class McpNestedReplacementPlan {

  /**
   * Parent pointer fields Entity Reference Revisions rewrites after save.
   *
   * @var list<string>
   */
  private const PARENT_FIELDS = [
    'parent_id',
    'parent_type',
    'parent_field_name',
  ];

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  private EntityTypeManagerInterface $entityTypeManager;

  /**
   * Host field that holds the direct paragraph.
   *
   * @var string
   */
  private string $fieldName;

  /**
   * Delta of the published parent on that field.
   *
   * @var int
   */
  private int $delta;

  /**
   * The new unpublished parent, not yet saved.
   *
   * @var \Drupal\Core\Entity\ContentEntityInterface
   */
  private ContentEntityInterface $newParent;

  /**
   * Published host entity id.
   *
   * @var string
   */
  private string $hostId;

  /**
   * Published host revision id captured before the write.
   *
   * @var string
   */
  private string $hostRevisionId;

  /**
   * Published host pin keys, uuid#revision, in field order.
   *
   * @var list<string>
   */
  private array $hostPinKeys;

  /**
   * Published paragraph revisions that must survive the save.
   *
   * @var list<array{id: string, revision_id: string, values: array<string, array<string, mixed>>}>
   */
  private array $watched;

  /**
   * Constructs a plan.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param string $field_name
   *   The host field.
   * @param int $delta
   *   The parent slot.
   * @param \Drupal\Core\Entity\ContentEntityInterface $new_parent
   *   The unsaved replacement parent.
   * @param string $host_id
   *   The published host id.
   * @param string $host_revision_id
   *   The published host revision id.
   * @param list<string> $host_pin_keys
   *   Published pin keys.
   * @param list<array{id: string, revision_id: string, values: array<string, array<string, mixed>>}> $watched
   *   Paragraph snapshots.
   */
  public function __construct(EntityTypeManagerInterface $entity_type_manager, string $field_name, int $delta, ContentEntityInterface $new_parent, string $host_id, string $host_revision_id, array $host_pin_keys, array $watched) {
    $this->entityTypeManager = $entity_type_manager;
    $this->fieldName = $field_name;
    $this->delta = $delta;
    $this->newParent = $new_parent;
    $this->hostId = $host_id;
    $this->hostRevisionId = $host_revision_id;
    $this->hostPinKeys = $host_pin_keys;
    $this->watched = $watched;
  }

  /**
   * Refuses the write when a published paragraph moved after planning.
   */
  public function confirmBaseline(): void {
    if (!$this->publishedIsUnchanged() || !$this->watchedUnchanged()) {
      throw new ConflictHttpException('The published component changed while this request was prepared. Reload before retrying.');
    }
  }

  /**
   * Attaches the new parent to the draft slot.
   *
   * Other slots keep target ids only, so their paragraph objects are not
   * placed on the field item here. The new parent replaces the published
   * parent object that was already on this slot.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $draft
   *   The draft about to be saved.
   */
  public function apply(ContentEntityInterface $draft): void {
    $host = $draft->getUntranslated();
    $values = [];
    foreach ($host->get($this->fieldName) as $item) {
      $values[] = [
        'target_id' => $item->target_id,
        'target_revision_id' => $item->target_revision_id,
      ];
    }
    $values[$this->delta] = ['entity' => $this->newParent];
    $host->set($this->fieldName, $values);
  }

  /**
   * Restores published paragraphs or fails the surrounding transaction.
   *
   * Entity Reference Revisions post-save can rewrite parent_id,
   * parent_type, and parent_field_name on a kept child without creating a
   * revision. That rewrite is undone here. Any other change, including a
   * new revision of a paragraph the published host still pins, fails the
   * save so the transaction rolls back.
   */
  public function assertPublishedUntouched(): void {
    if (!$this->publishedIsUnchanged()) {
      throw new ConflictHttpException('Nested replacement changed the published revision; the save was rolled back.');
    }
    $storage = $this->paragraphStorage();
    foreach ($this->watched as $watched) {
      $storage->resetCache([$watched['id']]);
      $current = $storage->loadUnchanged($watched['id']);
      $revision = $this->loadParagraphRevision((int) $watched['revision_id']);
      if (!$current instanceof ContentEntityInterface
        || !$revision instanceof ContentEntityInterface
        || (string) $current->getRevisionId() !== $watched['revision_id']
        || (string) $revision->getRevisionId() !== $watched['revision_id']) {
        throw new ConflictHttpException('Nested replacement changed a published paragraph; the save was rolled back.');
      }
      $values = self::fieldValues($revision);
      if ($values === $watched['values']) {
        continue;
      }
      $changed = self::changedFields($watched['values'], $values);
      $unexpected = array_diff($changed, self::PARENT_FIELDS);
      if ($changed === [] || $unexpected !== []) {
        throw new ConflictHttpException('Nested replacement changed a published paragraph; the save was rolled back.');
      }
      $this->restoreParentPointers($revision, $watched['values']);
      $storage->resetCache([$watched['id']]);
      $restored = $this->loadParagraphRevision((int) $watched['revision_id']);
      $default = $storage->loadUnchanged($watched['id']);
      if (!$restored instanceof ContentEntityInterface
        || !$default instanceof ContentEntityInterface
        || (string) $default->getRevisionId() !== $watched['revision_id']
        || self::fieldValues($restored) !== $watched['values']) {
        throw new ConflictHttpException('Nested replacement changed a published paragraph; the save was rolled back.');
      }
    }
  }

  /**
   * Whether the published host revision and pin keys still match.
   *
   * @return bool
   *   TRUE when the published host is unchanged.
   */
  public function publishedIsUnchanged(): bool {
    $storage = $this->entityTypeManager->getStorage('node');
    if (!$storage instanceof RevisionableStorageInterface) {
      return FALSE;
    }
    $storage->resetCache([$this->hostId]);
    $host = $storage->loadUnchanged($this->hostId);
    if (!$host instanceof ContentEntityInterface) {
      return FALSE;
    }
    if ((string) $host->getRevisionId() !== $this->hostRevisionId) {
      return FALSE;
    }
    return $this->pinKeys($host) === $this->hostPinKeys;
  }

  /**
   * Stored field values for one paragraph, without loaded entity objects.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The paragraph revision.
   *
   * @return array<string, array<string, mixed>>
   *   Values keyed by langcode, then field name.
   */
  public static function fieldValues(ContentEntityInterface $entity): array {
    $values = [];
    foreach ($entity->getTranslationLanguages() as $langcode => $language) {
      $translation = $entity->getTranslation($langcode);
      foreach ($translation->getFields(FALSE) as $name => $field) {
        $items = [];
        $type = $field->getFieldDefinition()->getType();
        foreach ($field as $item) {
          if ($type === 'entity_reference_revisions') {
            $items[] = [
              'target_id' => $item->target_id === NULL ? NULL : (string) $item->target_id,
              'target_revision_id' => $item->target_revision_id === NULL ? NULL : (string) $item->target_revision_id,
            ];
            continue;
          }
          $value = $item->getValue();
          unset($value['entity']);
          ksort($value);
          $items[] = $value;
        }
        $values[$langcode][$name] = $items;
      }
      ksort($values[$langcode]);
    }
    ksort($values);
    return $values;
  }

  /**
   * Field names whose stored values differ.
   *
   * @param array<string, array<string, mixed>> $before
   *   The earlier snapshot.
   * @param array<string, array<string, mixed>> $after
   *   The later snapshot.
   *
   * @return list<string>
   *   Field names.
   */
  public static function changedFields(array $before, array $after): array {
    $names = [];
    $languages = array_unique(array_merge(array_keys($before), array_keys($after)));
    foreach ($languages as $langcode) {
      $left = $before[$langcode] ?? [];
      $right = $after[$langcode] ?? [];
      $fields = array_unique(array_merge(array_keys($left), array_keys($right)));
      foreach ($fields as $name) {
        if (($left[$name] ?? NULL) !== ($right[$name] ?? NULL)) {
          $names[$name] = $name;
        }
      }
    }
    return array_values($names);
  }

  /**
   * Whether every watched paragraph revision still matches its snapshot.
   */
  private function watchedUnchanged(): bool {
    $storage = $this->paragraphStorage();
    foreach ($this->watched as $watched) {
      $storage->resetCache([$watched['id']]);
      $current = $storage->loadUnchanged($watched['id']);
      $revision = $this->loadParagraphRevision((int) $watched['revision_id']);
      if (!$current instanceof ContentEntityInterface
        || !$revision instanceof ContentEntityInterface
        || (string) $current->getRevisionId() !== $watched['revision_id']
        || self::fieldValues($revision) !== $watched['values']) {
        return FALSE;
      }
    }
    return TRUE;
  }

  /**
   * Writes the snapshotted parent pointers back onto the same revision.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $revision
   *   The kept paragraph revision.
   * @param array<string, array<string, mixed>> $values
   *   The snapshot taken before the draft save.
   */
  private function restoreParentPointers(ContentEntityInterface $revision, array $values): void {
    $default_language = $revision->getUntranslated()->language()->getId();
    $stored = $values[$default_language] ?? [];
    foreach (self::PARENT_FIELDS as $name) {
      if (isset($stored[$name]) && $revision->hasField($name)) {
        $revision->set($name, $stored[$name]);
      }
    }
    $was_default = $revision->isDefaultRevision();
    $revision->setNewRevision(FALSE);
    $revision->isDefaultRevision($was_default);
    $revision->save();
  }

  /**
   * Pin keys for the host field.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $host
   *   The published host.
   *
   * @return list<string>
   *   uuid#revision keys in field order.
   */
  private function pinKeys(ContentEntityInterface $host): array {
    if (!$host->hasField($this->fieldName)) {
      return [];
    }
    $storage = $this->paragraphStorage();
    $keys = [];
    foreach ($host->get($this->fieldName) as $item) {
      $revision_id = $item->target_revision_id;
      if (!is_numeric($revision_id) || (int) $revision_id <= 0) {
        $keys[] = 'missing';
        continue;
      }
      $paragraph = $storage->loadRevision((int) $revision_id);
      $uuid = $paragraph instanceof ContentEntityInterface ? (string) $paragraph->uuid() : '';
      $keys[] = $uuid . '#' . $revision_id;
    }
    return $keys;
  }

  /**
   * Loads one paragraph revision from storage.
   *
   * @param int $revision_id
   *   The revision id.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface|null
   *   The revision, or NULL.
   */
  private function loadParagraphRevision(int $revision_id): ?ContentEntityInterface {
    $storage = $this->paragraphStorage();
    if (method_exists($storage, 'loadRevisionUnchanged')) {
      $entity = $storage->loadRevisionUnchanged($revision_id);
    }
    else {
      $cached = $storage->loadRevision($revision_id);
      if ($cached instanceof EntityInterface) {
        $storage->resetCache([(string) $cached->id()]);
      }
      $entity = $storage->loadRevision($revision_id);
    }
    return $entity instanceof ContentEntityInterface ? $entity : NULL;
  }

  /**
   * Returns paragraph storage.
   *
   * @return \Drupal\Core\Entity\RevisionableStorageInterface
   *   Paragraph storage.
   */
  private function paragraphStorage(): RevisionableStorageInterface {
    $storage = $this->entityTypeManager->getStorage('paragraph');
    if (!$storage instanceof RevisionableStorageInterface) {
      throw new ConflictHttpException('Paragraph storage is not revisionable.');
    }
    return $storage;
  }

}
