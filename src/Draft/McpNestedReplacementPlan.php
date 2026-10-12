<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Draft;

use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Drupal\Core\Entity\Sql\SqlContentEntityStorage;
use Drupal\Core\Field\FieldItemInterface;
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
   * Translation timestamp restored with a parent-pointer rewrite.
   *
   * Entity Reference Revisions advances this field while saving the new
   * parent pointer. It is not restored on its own: a timestamp-only edit
   * is a real change to the published paragraph.
   *
   * @var string
   */
  private const TRANSLATION_CHANGED_FIELD = 'content_translation_changed';

  /**
   * Revision flag restored with a parent-pointer rewrite.
   *
   * Core recomputes this flag on save for every translation whose stored
   * value is NULL. The pointer rewrite counts as a change, so a translation
   * that was not affected by its published revision reads as affected
   * afterwards. Like the timestamp, it is restored only with a pointer.
   *
   * @var string
   */
  private const TRANSLATION_AFFECTED_FIELD = 'revision_translation_affected';

  /**
   * Translation metadata restored only together with a parent pointer.
   *
   * @var list<string>
   */
  private const TRANSLATION_FIELDS = [
    self::TRANSLATION_CHANGED_FIELD,
    self::TRANSLATION_AFFECTED_FIELD,
  ];

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  private EntityTypeManagerInterface $entityTypeManager;

  /**
   * The database connection the draft transaction runs on.
   *
   * @var \Drupal\Core\Database\Connection
   */
  private Connection $database;

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
   * @param \Drupal\Core\Database\Connection $database
   *   The connection the draft transaction runs on.
   */
  public function __construct(EntityTypeManagerInterface $entity_type_manager, string $field_name, int $delta, ContentEntityInterface $new_parent, string $host_id, string $host_revision_id, array $host_pin_keys, array $watched, Connection $database) {
    $this->entityTypeManager = $entity_type_manager;
    $this->database = $database;
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
        'target_id' => self::pinValue($item, 'target_id'),
        'target_revision_id' => self::pinValue($item, 'target_revision_id'),
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
   * revision. On a translatable paragraph that save also advances
   * content_translation_changed, and sets revision_translation_affected
   * on any translation that stored NULL. Both are restored only when a
   * parent pointer changed with them. A change to either on its own, any
   * other field change, or a new revision of a paragraph the published
   * host still pins, fails the save so the transaction rolls back.
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
      $restorable = self::PARENT_FIELDS;
      if (array_intersect($changed, self::PARENT_FIELDS) !== []) {
        $restorable = array_merge($restorable, self::TRANSLATION_FIELDS);
      }
      if ($changed === [] || array_diff($changed, $restorable) !== []) {
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
            $target_id = self::pinValue($item, 'target_id');
            $revision_id = self::pinValue($item, 'target_revision_id');
            $items[] = [
              'target_id' => $target_id === NULL ? NULL : (string) $target_id,
              'target_revision_id' => $revision_id === NULL ? NULL : (string) $revision_id,
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
   * Also restores content_translation_changed on each translation. The
   * pointer save advances that timestamp, and a second save would advance
   * it again unless this write puts the snapshotted value back first.
   * The revision_translation_affected flag is written back after the
   * save, because the save recomputes it.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $revision
   *   The kept paragraph revision.
   * @param array<string, array<string, mixed>> $values
   *   The snapshot taken before the draft save.
   */
  private function restoreParentPointers(ContentEntityInterface $revision, array $values): void {
    $untranslated = $revision->getUntranslated();
    $default_language = $untranslated->language()->getId();
    $stored = $values[$default_language] ?? [];
    foreach (self::PARENT_FIELDS as $name) {
      if (isset($stored[$name]) && $untranslated->hasField($name)) {
        $untranslated->set($name, $stored[$name]);
      }
    }
    foreach ($values as $langcode => $translation_values) {
      $timestamp = $translation_values[self::TRANSLATION_CHANGED_FIELD]
        ?? NULL;
      if ($timestamp === NULL || !$revision->hasTranslation($langcode)) {
        continue;
      }
      $translation = $revision->getTranslation($langcode);
      if ($translation->hasField(self::TRANSLATION_CHANGED_FIELD)) {
        $translation->set(self::TRANSLATION_CHANGED_FIELD, $timestamp);
      }
    }
    $was_default = $revision->isDefaultRevision();
    $revision->setNewRevision(FALSE);
    $revision->isDefaultRevision($was_default);
    $revision->save();
    $this->restoreTranslationAffected($revision, $values);
  }

  /**
   * Writes the snapshotted revision_translation_affected flags back.
   *
   * Core's storage recomputes the flag for every translation that stores
   * NULL, on every save, from the entity's changes. The restore save above
   * changes the parent pointer back, so a translation that was unaffected
   * by its published revision would be stored as affected. Only a direct
   * write can keep NULL. The write stays inside the draft transaction and
   * covers both the data table and the revision data table, so a rollback
   * undoes it with everything else.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $revision
   *   The kept paragraph revision, already saved.
   * @param array<string, array<string, mixed>> $values
   *   The snapshot taken before the draft save.
   */
  private function restoreTranslationAffected(ContentEntityInterface $revision, array $values): void {
    $storage = $this->paragraphStorage();
    if (!$storage instanceof SqlContentEntityStorage
      || !$revision->hasField(self::TRANSLATION_AFFECTED_FIELD)) {
      return;
    }
    $entity_type = $revision->getEntityType();
    $id_key = $entity_type->getKey('id');
    $revision_key = $entity_type->getKey('revision');
    $langcode_key = $entity_type->getKey('langcode');
    if (!is_string($id_key) || !is_string($revision_key) || !is_string($langcode_key)) {
      return;
    }
    $definition = $revision->getFieldDefinition(self::TRANSLATION_AFFECTED_FIELD);
    if ($definition === NULL) {
      return;
    }
    $column = $storage->getTableMapping()
      ->getFieldColumnName($definition->getFieldStorageDefinition(), 'value');
    $tables = [
      [$storage->getDataTable(), $id_key, $revision->id()],
      [$storage->getRevisionDataTable(), $revision_key, $revision->getRevisionId()],
    ];
    foreach ($values as $langcode => $translation_values) {
      if (!array_key_exists(self::TRANSLATION_AFFECTED_FIELD, $translation_values)
        || !$revision->hasTranslation($langcode)) {
        continue;
      }
      $items = $translation_values[self::TRANSLATION_AFFECTED_FIELD];
      $value = is_array($items) ? ($items[0]['value'] ?? NULL) : NULL;
      $flag = $value === NULL ? NULL : (int) (bool) $value;
      foreach ($tables as [$table, $key, $key_value]) {
        if (!is_string($table)) {
          continue;
        }
        $this->database->update($table)
          ->fields([$column => $flag])
          ->condition($key, $key_value)
          ->condition($revision_key, $revision->getRevisionId())
          ->condition($langcode_key, $langcode)
          ->execute();
      }
    }
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
    $storage = $this->paragraphRevisions();
    $keys = [];
    foreach ($host->get($this->fieldName) as $item) {
      $revision_id = self::pinValue($item, 'target_revision_id');
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
    $storage = $this->paragraphRevisions();
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
   * The declared type stays EntityStorageInterface. phpstan-drupal maps
   * load() and create() on RevisionableStorageInterface to one arbitrary
   * revisionable entity, which would hide the real paragraph type.
   *
   * @return \Drupal\Core\Entity\EntityStorageInterface
   *   Paragraph storage.
   */
  private function paragraphStorage(): EntityStorageInterface {
    $storage = $this->entityTypeManager->getStorage('paragraph');
    if (!$storage instanceof RevisionableStorageInterface) {
      throw new ConflictHttpException('Paragraph storage is not revisionable.');
    }
    return $storage;
  }

  /**
   * Narrows paragraph storage for revision reads.
   *
   * @return \Drupal\Core\Entity\RevisionableStorageInterface
   *   Paragraph storage.
   */
  private function paragraphRevisions(): RevisionableStorageInterface {
    $storage = $this->paragraphStorage();
    if (!$storage instanceof RevisionableStorageInterface) {
      throw new ConflictHttpException('Paragraph storage is not revisionable.');
    }
    return $storage;
  }

  /**
   * Reads one stored column from a field item.
   *
   * The item class is not known here, so the value comes from getValue()
   * rather than a property.
   *
   * @param \Drupal\Core\Field\FieldItemInterface $item
   *   The field item.
   * @param string $key
   *   The column name.
   *
   * @return mixed
   *   The stored value, or NULL when the column is absent.
   */
  private static function pinValue(FieldItemInterface $item, string $key): mixed {
    $value = $item->getValue();
    return $value[$key] ?? NULL;
  }

}
