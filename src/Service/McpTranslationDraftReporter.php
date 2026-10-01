<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\TranslatableRevisionableStorageInterface;
use Drupal\Core\Session\AccountInterface;

/**
 * Per-language pending-draft inventory for governed translations.
 *
 * After revise-over-working (#3626570) a node can hold one language's draft
 * on the tip and another's on an earlier revision. Inventory and notices
 * read each language from getLatestTranslationAffectedRevisionId() so a
 * carried-forward published moderation record is not reported as "no draft"
 * (#3626610, #3626879).
 */
final class McpTranslationDraftReporter {

  /**
   * Notice code when more than one language has a pending draft.
   */
  public const NOTICE_CODE = 'multi_pending_publish';

  /**
   * Entity types that use unpublished forward revisions.
   *
   * @var list<string>
   */
  private const FORWARD_ENTITY_TYPES = ['node', 'media'];

  /**
   * Maximum entities inspected for the status-report listing.
   */
  private const SCAN_CAP = 200;

  /**
   * Maximum multi-pending entities listed on the status report.
   */
  private const LIST_CAP = 25;

  /**
   * Constructs the reporter.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   Content moderation, or NULL when that module is absent.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * Stable notice that publishing one pending language drops the others.
   *
   * @return array{code: string, detail: string}
   *   Machine code and operator-facing detail.
   */
  public function multiPendingPublishNotice(): array {
    return [
      'code' => self::NOTICE_CODE,
      'detail' => 'This entity has pending drafts in more than one language. '
        . 'Publishing one language in the Drupal UI drops the other pending '
        . 'drafts: core builds the new default revision from the published '
        . 'language and takes every other language from the previous default. '
        . 'The dropped draft remains in revision history. Re-draft it from that '
        . 'language\'s last draft revision (working_vid on GET '
        . '.../mcp-translations). Sentinel does not hide this core behavior.',
    ];
  }

  /**
   * Pending drafts keyed from each language's latest-affected revision.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $live
   *   The live default revision.
   * @param \Drupal\Core\Entity\TranslatableRevisionableStorageInterface $storage
   *   Revision storage for the entity.
   * @param \Drupal\Core\Session\AccountInterface|null $account
   *   When set, omit languages whose affected revision is not viewable.
   *
   * @return list<array<string, mixed>>
   *   Compact pending rows (langcode, vid, title, status, moderation).
   */
  public function pendingLanguages(
    ContentEntityInterface $live,
    TranslatableRevisionableStorageInterface $storage,
    ?AccountInterface $account = NULL,
  ): array {
    $pending = [];
    $default = $live->getUntranslated()->language()->getId();
    $languages = $this->languageCodes($live, $storage);
    foreach ($languages as $langcode) {
      $row = $this->languageFromLatestAffected($live, $storage, $langcode, $default, $account);
      if ($row !== NULL && !empty($row['pending'])) {
        $pending[] = [
          'langcode' => $row['langcode'],
          'vid' => $row['working_vid'],
          'title' => $row['title'],
          'status' => $row['status'],
          'default' => $row['default'],
          'moderation_state' => $row['moderation_state'] ?? NULL,
        ];
      }
    }
    return $pending;
  }

  /**
   * Adds per-language working_vid / pending onto a tip working summary.
   *
   * Each language's title, status, and moderation come from its latest
   * translation-affected revision, not from the tip, so a language carried
   * forward as unpublished + published moderation is not reported as live.
   *
   * @param array{vid: string, translations: list<array<string, mixed>>} $working
   *   Tip-revision summary from the draft controller.
   * @param \Drupal\Core\Entity\ContentEntityInterface $live
   *   The live default revision.
   * @param \Drupal\Core\Entity\TranslatableRevisionableStorageInterface $storage
   *   Revision storage.
   * @param \Drupal\Core\Entity\ContentEntityInterface $tip
   *   The latest (tip) working revision.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The caller; used to decide whether an earlier revision may be read.
   *
   * @return array{vid: string, translations: list<array<string, mixed>>}
   *   The same shape with working_vid, pending, and affected on each row.
   */
  public function decorateWorkingInventory(
    array $working,
    ContentEntityInterface $live,
    TranslatableRevisionableStorageInterface $storage,
    ContentEntityInterface $tip,
    AccountInterface $account,
  ): array {
    $default = $live->getUntranslated()->language()->getId();
    $seen = [];
    $translations = [];
    foreach ($working['translations'] as $row) {
      if (!is_string($row['langcode'] ?? NULL)) {
        continue;
      }
      $seen[] = $row['langcode'];
      $translations[] = $this->decorateTranslationRow($row, $live, $storage, $tip, $default, $account);
    }
    foreach ($this->languageCodes($live, $storage) as $langcode) {
      if (in_array($langcode, $seen, TRUE)) {
        continue;
      }
      $extra = $this->languageFromLatestAffected($live, $storage, $langcode, $default, $account);
      if ($extra !== NULL && !empty($extra['pending'])) {
        $translations[] = $extra;
      }
    }
    $working['translations'] = $translations;
    return $working;
  }

  /**
   * Entities that currently hold pending drafts in more than one language.
   *
   * @return list<array{entity_type: string, id: string, label: string, languages: list<string>}>
   *   A capped listing for the status report.
   */
  public function findMultiPendingEntities(): array {
    $found = [];
    foreach (self::FORWARD_ENTITY_TYPES as $entity_type_id) {
      if (!$this->entityTypeManager->hasDefinition($entity_type_id)) {
        continue;
      }
      $storage = $this->entityTypeManager->getStorage($entity_type_id);
      if (!method_exists($storage, 'getLatestTranslationAffectedRevisionId')) {
        continue;
      }
      // Node and media storage implement the translatable-revision contract.
      /** @var \Drupal\Core\Entity\TranslatableRevisionableStorageInterface $storage */
      foreach ($this->idsWithForwardRevision($entity_type_id) as $id) {
        $live = $storage->loadUnchanged($id);
        if (!$live instanceof ContentEntityInterface) {
          continue;
        }
        $pending = $this->pendingLanguages($live, $storage);
        if (count($pending) < 2) {
          continue;
        }
        $found[] = [
          'entity_type' => $entity_type_id,
          'id' => (string) $live->id(),
          'label' => (string) $live->label(),
          'languages' => array_map(
            static fn(array $row): string => (string) $row['langcode'],
            $pending,
          ),
        ];
        if (count($found) >= self::LIST_CAP) {
          return $found;
        }
      }
    }
    return $found;
  }

  /**
   * Rebuilds one working-row from the language's latest-affected revision.
   *
   * @param array<string, mixed> $row
   *   Tip-revision language row.
   * @param \Drupal\Core\Entity\ContentEntityInterface $live
   *   The live default revision.
   * @param \Drupal\Core\Entity\TranslatableRevisionableStorageInterface $storage
   *   Revision storage.
   * @param \Drupal\Core\Entity\ContentEntityInterface $tip
   *   The tip working revision.
   * @param string $default
   *   Default langcode.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The caller.
   *
   * @return array<string, mixed>
   *   Decorated row.
   */
  private function decorateTranslationRow(
    array $row,
    ContentEntityInterface $live,
    TranslatableRevisionableStorageInterface $storage,
    ContentEntityInterface $tip,
    string $default,
    AccountInterface $account,
  ): array {
    $langcode = (string) $row['langcode'];
    $affected = $this->languageFromLatestAffected($live, $storage, $langcode, $default, $account);
    if ($affected !== NULL) {
      $affected['affected'] = $this->tipAffects($tip, $langcode);
      return $affected;
    }
    $row['working_vid'] = (string) $tip->getRevisionId();
    $row['pending'] = FALSE;
    $row['affected'] = $this->tipAffects($tip, $langcode);
    return $row;
  }

  /**
   * Summary of one language from its latest translation-affected revision.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $live
   *   The live default revision.
   * @param \Drupal\Core\Entity\TranslatableRevisionableStorageInterface $storage
   *   Revision storage.
   * @param string $langcode
   *   Language to report.
   * @param string $default
   *   Default langcode.
   * @param \Drupal\Core\Session\AccountInterface|null $account
   *   When set, refuse to replace the row with an unreadable revision.
   *
   * @return array<string, mixed>|null
   *   Row including working_vid and pending, or NULL when the language is
   *   absent.
   */
  private function languageFromLatestAffected(
    ContentEntityInterface $live,
    TranslatableRevisionableStorageInterface $storage,
    string $langcode,
    string $default,
    ?AccountInterface $account,
  ): ?array {
    $affected_id = $storage->getLatestTranslationAffectedRevisionId($live->id(), $langcode);
    if ($affected_id === NULL) {
      return NULL;
    }
    $source = $storage->loadRevision($affected_id);
    if (!$source instanceof ContentEntityInterface || !$source->hasTranslation($langcode)) {
      return NULL;
    }
    $translation = $source->getTranslation($langcode);
    $readable = $account === NULL || $source->access('view', $account);
    if (!$readable) {
      return NULL;
    }
    $row = $this->translationRow($translation, $default);
    $row['working_vid'] = (string) $affected_id;
    $row['pending'] = $this->isPending($translation, $live, (string) $affected_id);
    $row['affected'] = FALSE;
    return $row;
  }

  /**
   * Compact per-language fields shared with the inventory.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $translation
   *   One translation of a revision.
   * @param string $default
   *   Default langcode.
   *
   * @return array<string, mixed>
   *   langcode, default, status, title, and optional moderation/source.
   */
  private function translationRow(ContentEntityInterface $translation, string $default): array {
    $langcode = $translation->language()->getId();
    $row = [
      'langcode' => $langcode,
      'default' => $langcode === $default,
      'status' => $translation instanceof EntityPublishedInterface
        ? $translation->isPublished()
        : NULL,
      'title' => $translation->label(),
    ];
    if ($translation->hasField('moderation_state')) {
      $row['moderation_state'] = $translation->get('moderation_state')->value;
    }
    if ($translation->hasField('content_translation_outdated')) {
      $row['outdated'] = (bool) $translation->get('content_translation_outdated')->value;
    }
    if ($translation->hasField('content_translation_source')) {
      $source = $translation->get('content_translation_source')->value;
      if (is_string($source) && $source !== '') {
        $row['source'] = $source;
      }
    }
    return $row;
  }

  /**
   * Whether this latest-affected translation is still a pending draft.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $translation
   *   The translation on its latest-affected revision.
   * @param \Drupal\Core\Entity\ContentEntityInterface $live
   *   The live default revision.
   * @param string $affected_id
   *   That language's latest-affected revision id.
   *
   * @return bool
   *   TRUE when the draft is ahead of live.
   */
  private function isPending(
    ContentEntityInterface $translation,
    ContentEntityInterface $live,
    string $affected_id,
  ): bool {
    if ($affected_id === (string) $live->getRevisionId()) {
      return FALSE;
    }
    if ($translation instanceof EntityPublishedInterface && !$translation->isPublished()) {
      return TRUE;
    }
    if (!$translation->hasField('moderation_state') || !$this->moderationInformation) {
      return FALSE;
    }
    if (!$this->moderationInformation->isModeratedEntity($translation)) {
      return FALSE;
    }
    $state_id = $translation->get('moderation_state')->value;
    if (!is_string($state_id) || $state_id === '') {
      return FALSE;
    }
    $state = $this->moderationInformation->getWorkflowForEntity($translation)
      ->getTypePlugin()
      ->getState($state_id);
    return $state instanceof ContentModerationState
      && !$state->isPublishedState()
      && !$state->isDefaultRevisionState();
  }

  /**
   * Whether the tip revision marks this language as translation-affected.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $tip
   *   The tip working revision.
   * @param string $langcode
   *   Language to inspect.
   *
   * @return bool
   *   TRUE when the tip is this language's latest-affected revision.
   */
  private function tipAffects(ContentEntityInterface $tip, string $langcode): bool {
    if (!$tip->hasTranslation($langcode)) {
      return FALSE;
    }
    return (bool) $tip->getTranslation($langcode)->isRevisionTranslationAffected();
  }

  /**
   * Language codes present on live or on any latest-affected revision.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $live
   *   The live default revision.
   * @param \Drupal\Core\Entity\TranslatableRevisionableStorageInterface $storage
   *   Revision storage.
   *
   * @return list<string>
   *   Unique langcodes.
   */
  private function languageCodes(
    ContentEntityInterface $live,
    TranslatableRevisionableStorageInterface $storage,
  ): array {
    $codes = [];
    foreach ($live->getTranslationLanguages() as $language) {
      $codes[] = $language->getId();
    }
    $latest_id = $storage->getLatestRevisionId($live->id());
    if ($latest_id !== NULL && (string) $latest_id !== (string) $live->getRevisionId()) {
      $tip = $storage->loadRevision($latest_id);
      if ($tip instanceof ContentEntityInterface) {
        foreach ($tip->getTranslationLanguages() as $language) {
          $codes[] = $language->getId();
        }
      }
    }
    return array_values(array_unique($codes));
  }

  /**
   * Entity ids whose latest revision is not the default revision.
   *
   * @param string $entity_type_id
   *   Node or media.
   *
   * @return list<string>
   *   A capped list of ids, newest first.
   */
  private function idsWithForwardRevision(string $entity_type_id): array {
    $entity_type = $this->entityTypeManager->getDefinition($entity_type_id);
    $base_table = $entity_type->getBaseTable();
    $revision_table = $entity_type->getRevisionTable();
    $id_key = $entity_type->getKey('id');
    $revision_key = $entity_type->getKey('revision');
    if (!is_string($base_table) || !is_string($revision_table)
      || !is_string($id_key) || !is_string($revision_key)
      || !$this->database->schema()->tableExists($revision_table)
      || !$this->database->schema()->tableExists($base_table)) {
      return [];
    }
    $latest = $this->database->select($revision_table, 'r');
    $latest->addField('r', $id_key, 'id');
    $latest->addExpression('MAX(r.' . $revision_key . ')', 'latest_vid');
    $latest->groupBy('r.' . $id_key);
    $latest_map = $latest->execute()->fetchAllKeyed();
    $defaults = $this->database->select($base_table, 'b')
      ->fields('b', [$id_key, $revision_key])
      ->execute()
      ->fetchAllKeyed();
    $mismatched = [];
    foreach ($latest_map as $id => $latest_vid) {
      if ((string) $latest_vid !== (string) ($defaults[$id] ?? '')) {
        $mismatched[] = (string) $id;
      }
    }
    rsort($mismatched, SORT_NUMERIC);
    return array_slice($mismatched, 0, self::SCAN_CAP);
  }

}
