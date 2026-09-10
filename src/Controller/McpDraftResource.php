<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Component\Serialization\Json;
use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\jsonapi\Controller\EntityResource;
use Drupal\jsonapi\JsonApiResource\JsonApiDocumentTopLevel;
use Drupal\jsonapi\JsonApiResource\ResourceObject;
use Drupal\jsonapi\JsonApiResource\ResourceObjectData;
use Drupal\jsonapi\ResourceType\ResourceType;
use Drupal\jsonapi\ResourceResponse;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\node\NodeInterface;
use Drupal\node\NodeStorageInterface;
use Drupal\user\UserInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

/**
 * Continues an unpublished node draft without replacing its live revision.
 *
 * Uses core's JSON:API deserialization, field access, validation and response
 * handling. Only the unsupported revision-write controller step is replaced.
 * This dependency on core's internal controller is covered by functional tests.
 *
 * Translation create/update uses the same revision pointers plus
 * X-MCP-Draft-Langcode so a Spanish draft can sit beside published English.
 *
 * @phpstan-ignore classExtendsInternalClass.classExtendsInternalClass (Core adapter verified across the supported Drupal matrix.)
 */
final class McpDraftResource extends EntityResource {

  /**
   * Header that selects the translation to create, read, or continue.
   */
  public const LANGCODE_HEADER = 'X-MCP-Draft-Langcode';

  /**
   * Bookkeeping fields that a translation write must never copy.
   */
  private const SKIP_FIELD_NAMES = [
    'langcode',
    'default_langcode',
    'revision_translation_affected',
    'revision_default',
    'content_translation_source',
    'content_translation_outdated',
    'content_translation_uid',
    'content_translation_status',
    'content_translation_created',
    'vid',
    'nid',
    'uuid',
    'created',
    'changed',
    'revision_timestamp',
    'revision_uid',
    'revision_log',
  ];

  /**
   * The database connection.
   */
  protected Connection $draftDatabase;

  /**
   * The governance resolver.
   */
  protected McpPolicyResolver $draftPolicy;

  /**
   * Optional content moderation information.
   */
  protected ?ModerationInformationInterface $draftModeration;

  /**
   * The language manager.
   */
  protected LanguageManagerInterface $languageManager;

  /**
   * Optional content-translation manager.
   *
   * Absent when the module is not installed.
   */
  protected mixed $translationManager = NULL;

  /**
   * Injects draft services without duplicating core's controller constructor.
   */
  public function setDraftServices(Connection $database, McpPolicyResolver $policy, ?ModerationInformationInterface $moderation, LanguageManagerInterface $language_manager, mixed $translation_manager = NULL): void {
    $this->draftDatabase = $database;
    $this->draftPolicy = $policy;
    $this->draftModeration = $moderation;
    $this->languageManager = $language_manager;
    $this->translationManager = $translation_manager;
  }

  /**
   * Continues a draft or returns a no-save preflight response.
   *
   * Validation, including node-reference access queries, runs outside the
   * exclusive write transaction. Holding that transaction across nested
   * SELECTs trips core #2920527 on PostgreSQL (duplicate
   * mimic_implicit_commit savepoint). Preflight never opens a transaction:
   * it is not a reservation. The write still row-locks, re-checks both
   * revision pointers, and rolls back if the live revision would change.
   *
   * A multilingual working revision requires X-MCP-Draft-Langcode. The
   * selected translation is the entity that is validated and saved so
   * content_moderation sees that translation's unpublished state.
   *
   * @return \Drupal\jsonapi\ResourceResponse|\Symfony\Component\HttpFoundation\JsonResponse
   *   The saved resource or preflight metadata.
   */
  public function patchIndividual(ResourceType $resource_type, EntityInterface $entity, Request $request): ResourceResponse|JsonResponse {
    $this->assertGovernedNode($entity);
    $versions = $this->parseRevisionMatch($request, FALSE);
    $langcode = $this->requestLangcode($request, FALSE);
    $preflight = $this->parsePreflight($request);
    /** @var \Drupal\node\NodeStorageInterface $storage */
    $storage = $this->entityTypeManager->getStorage('node');
    $live = $this->assertRevisionPointers(
      $storage->loadUnchanged($entity->id()),
      $storage->getLatestRevisionId($entity->id()),
      $versions,
    );
    $draft = $this->loadWorkingDraft($storage, $entity, $versions[2], $langcode);
    if (!$draft->access('update', $this->user)) {
      throw new AccessDeniedHttpException('Draft update access denied.');
    }
    $this->assertTranslationNotDefaultRevisionState($draft);
    // Core's deserialize() docblock says array, but this normalizer returns
    // the content entity. Keep the actual contract explicit here.
    /** @var \Drupal\node\NodeInterface $parsed */
    $parsed = $this->deserialize($resource_type, $request, JsonApiDocumentTopLevel::class);
    $data = $this->requestData($request);
    if (($data['id'] ?? NULL) !== $draft->uuid()) {
      throw new BadRequestHttpException('The selected entity does not match the ID in the payload.');
    }
    $this->applySubmittedDraftFields($resource_type, $parsed, $draft, $live, $data, $langcode !== NULL);
    $this->assertDraftRemainsUnpublished($draft);
    // Include entity-level governance constraints, not only changed fields.
    static::validate($draft);
    if ($preflight === '1') {
      return $this->preflightResponse($versions, $langcode);
    }
    return $this->saveForwardRevision($storage, $entity, $draft, $resource_type, $request, $versions);
  }

  /**
   * Creates a target-language translation as an unpublished forward revision.
   *
   * If-Match is `"live"` when no working revision exists, or `"live:working"`
   * when adding the language onto an existing unpublished forward revision.
   * An existing translation on live or working is a conflict, not an overwrite.
   *
   * @return \Drupal\jsonapi\ResourceResponse|\Symfony\Component\HttpFoundation\JsonResponse
   *   The saved translation resource or preflight metadata.
   */
  public function postTranslation(ResourceType $resource_type, EntityInterface $entity, Request $request): ResourceResponse|JsonResponse {
    $this->assertGovernedNode($entity);
    $versions = $this->parseRevisionMatch($request, TRUE);
    $langcode = $this->requestLangcode($request, TRUE);
    $this->assertEnabledLanguage($langcode);
    $preflight = $this->parsePreflight($request);
    /** @var \Drupal\node\NodeStorageInterface $storage */
    $storage = $this->entityTypeManager->getStorage('node');
    $latest_id = $storage->getLatestRevisionId($entity->id());
    $live = $storage->loadUnchanged($entity->id());
    if (!$live instanceof NodeInterface) {
      throw new ConflictHttpException('The live or working revision changed. Reload before retrying.');
    }
    $this->assertCreateRevisionPointers($live, $latest_id, $versions);
    if ($live->language()->getId() === $langcode) {
      throw new BadRequestHttpException('The target language is already the default language.');
    }
    $this->assertBundleTranslatable($live);
    $base = $this->loadCreateBase($storage, $live, $versions, $latest_id);
    if ($live->hasTranslation($langcode) || $base->hasTranslation($langcode)) {
      throw new ConflictHttpException('A translation for this language already exists. Continue it instead of creating it.');
    }
    if (!$base->access('update', $this->user)) {
      throw new AccessDeniedHttpException('Draft update access denied.');
    }
    $this->mergeDefaultTranslations($base, $live);
    $source = $base->getUntranslated();
    $translation = $base->addTranslation($langcode, $source->toArray());
    $translation->setRevisionTranslationAffected(NULL);
    $translation->setUnpublished();
    if ($translation->hasField('moderation_state')) {
      $translation->set('moderation_state', 'draft');
    }
    $this->applyTranslationMetadata($translation, $source->language()->getId());
    // Core's deserialize() docblock says array, but this normalizer returns
    // the content entity. Keep the actual contract explicit here.
    /** @var \Drupal\node\NodeInterface $parsed */
    $parsed = $this->deserialize($resource_type, $request, JsonApiDocumentTopLevel::class);
    $data = $this->requestData($request);
    if (($data['id'] ?? NULL) !== $base->uuid()) {
      throw new BadRequestHttpException('The selected entity does not match the ID in the payload.');
    }
    $this->applySubmittedDraftFields($resource_type, $parsed, $translation, $live, $data, TRUE);
    $this->assertDraftRemainsUnpublished($translation);
    static::validate($translation);
    $save_versions = [
      1 => (string) $live->getRevisionId(),
      2 => (string) $base->getRevisionId(),
    ];
    if ($preflight === '1') {
      return $this->preflightResponse($save_versions, $langcode);
    }
    return $this->saveForwardRevision($storage, $entity, $translation, $resource_type, $request, $save_versions, TRUE);
  }

  /**
   * Returns live and working translation inventories without field bodies.
   *
   * Working-revision languages are omitted unless the principal can view that
   * unpublished revision, so anonymous callers cannot probe for a draft.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   Inventory metadata.
   */
  public function getTranslationInventory(ResourceType $resource_type, EntityInterface $entity, Request $request): JsonResponse {
    $this->assertGovernedNode($entity);
    /** @var \Drupal\node\NodeStorageInterface $storage */
    $storage = $this->entityTypeManager->getStorage('node');
    $live = $storage->loadUnchanged($entity->id());
    if (!$live instanceof NodeInterface) {
      throw new ConflictHttpException('The live revision is no longer available.');
    }
    if (!$live->access('view', $this->user)) {
      throw new AccessDeniedHttpException('Translation inventory access denied.');
    }
    $latest_id = $storage->getLatestRevisionId($entity->id());
    $payload = [
      'defaultLangcode' => $live->getUntranslated()->language()->getId(),
      'live' => $this->summarizeRevisionTranslations($live),
      'working' => NULL,
    ];
    if ((string) $latest_id !== (string) $live->getRevisionId()) {
      $working = $storage->loadRevision($latest_id);
      if ($working instanceof NodeInterface && $working->access('view', $this->user)) {
        $payload['working'] = $this->summarizeRevisionTranslations($working);
      }
    }
    return new JsonResponse(['meta' => $payload], 200, ['Cache-Control' => 'no-store']);
  }

  /**
   * Returns one translation of the named working revision.
   *
   * @return \Drupal\jsonapi\ResourceResponse
   *   The translation as a JSON:API resource.
   */
  public function getDraftTranslation(ResourceType $resource_type, EntityInterface $entity, Request $request): ResourceResponse {
    $this->assertGovernedNode($entity);
    $versions = $this->parseRevisionMatch($request, FALSE);
    $langcode = $this->requestLangcode($request, TRUE);
    /** @var \Drupal\node\NodeStorageInterface $storage */
    $storage = $this->entityTypeManager->getStorage('node');
    $this->assertRevisionPointers(
      $storage->loadUnchanged($entity->id()),
      $storage->getLatestRevisionId($entity->id()),
      $versions,
    );
    $draft = $this->loadWorkingDraft($storage, $entity, $versions[2], $langcode);
    if (!$draft->access('view', $this->user)) {
      throw new AccessDeniedHttpException('Draft translation access denied.');
    }
    $primary_data = new ResourceObjectData([ResourceObject::createFromEntity($resource_type, $draft)], 1);
    /** @var \Drupal\jsonapi\JsonApiResource\IncludedData $includes */
    $includes = $this->getIncludes($request, $primary_data);
    $response = $this->buildWrappedResponse($primary_data, $request, $includes);
    $response->headers->set('Cache-Control', 'no-store');
    return $response;
  }

  /**
   * Refuses traffic that is not a governed node update.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The route entity.
   *
   * @phpstan-assert NodeInterface $entity
   */
  private function assertGovernedNode(EntityInterface $entity): void {
    if (!$entity instanceof NodeInterface || !$this->draftPolicy->isGoverned()) {
      throw new AccessDeniedHttpException('Draft continuation requires a governed node update.');
    }
  }

  /**
   * Parses If-Match into live and optional working revision ids.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   * @param bool $allow_live_only
   *   TRUE when `"live"` (no working pointer) is accepted.
   *
   * @return array<int, string>
   *   Preg-style captures: [1] live id, [2] working id (empty when omitted).
   */
  private function parseRevisionMatch(Request $request, bool $allow_live_only): array {
    $match = $request->headers->get('If-Match', '');
    if (preg_match('/^"([1-9][0-9]*):([1-9][0-9]*)"$/D', $match, $versions)) {
      return $versions;
    }
    if ($allow_live_only && preg_match('/^"([1-9][0-9]*)"$/D', $match, $versions)) {
      $versions[2] = '';
      return $versions;
    }
    throw new BadRequestHttpException('If-Match must identify the live and working revision IDs as "live:working".');
  }

  /**
   * Returns the JSON:API `data` object from the request body.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return array<string, mixed>
   *   The `data` member.
   */
  private function requestData(Request $request): array {
    $document = Json::decode($request->getContent());
    if (!is_array($document) || !isset($document['data']) || !is_array($document['data'])) {
      throw new BadRequestHttpException('The request document is invalid.');
    }
    return $document['data'];
  }

  /**
   * Reads and validates X-MCP-Draft-Preflight.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return string
   *   '0' or '1'.
   */
  private function parsePreflight(Request $request): string {
    $preflight = $request->headers->get('X-MCP-Draft-Preflight', '0');
    if (!in_array($preflight, ['0', '1'], TRUE)) {
      throw new BadRequestHttpException('X-MCP-Draft-Preflight must be 0 or 1.');
    }
    return $preflight;
  }

  /**
   * Reads X-MCP-Draft-Langcode.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   * @param bool $required
   *   Whether a missing header is an error.
   *
   * @return string|null
   *   The langcode, or NULL when omitted and not required.
   */
  private function requestLangcode(Request $request, bool $required): ?string {
    $langcode = trim((string) $request->headers->get(self::LANGCODE_HEADER, ''));
    if ($langcode === '') {
      if ($required) {
        throw new BadRequestHttpException('X-MCP-Draft-Langcode is required.');
      }
      return NULL;
    }
    if (!preg_match('/^[a-z]{1,8}([_-][a-z0-9]{1,8})?$/D', $langcode)) {
      throw new BadRequestHttpException('X-MCP-Draft-Langcode is not a valid language code.');
    }
    return $langcode;
  }

  /**
   * Refuses a language that is not enabled on the site.
   *
   * @param string $langcode
   *   The requested language.
   */
  private function assertEnabledLanguage(string $langcode): void {
    if ($this->languageManager->getLanguage($langcode) === NULL) {
      throw new BadRequestHttpException('The requested language is not enabled.');
    }
  }

  /**
   * Refuses a bundle that cannot store translations.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The node.
   */
  private function assertBundleTranslatable(NodeInterface $node): void {
    if (!$node->isTranslatable()) {
      throw new BadRequestHttpException('This entity is not translatable.');
    }
    if (is_object($this->translationManager)
      && method_exists($this->translationManager, 'isEnabled')
      && !$this->translationManager->isEnabled('node', $node->bundle())) {
      throw new BadRequestHttpException('This bundle is not configured as translatable.');
    }
  }

  /**
   * Builds the no-save preflight payload.
   *
   * @param array<int, string> $versions
   *   Live and working revision ids.
   * @param string|null $langcode
   *   The selected language, if any.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   Preflight metadata.
   */
  private function preflightResponse(array $versions, ?string $langcode): JsonResponse {
    $meta = [
      'draft_preflight' => TRUE,
      'live' => $versions[1],
      'working' => $versions[2],
    ];
    if ($langcode !== NULL) {
      $meta['langcode'] = $langcode;
    }
    return new JsonResponse(['meta' => $meta], 200, ['Cache-Control' => 'no-store']);
  }

  /**
   * Saves a new unpublished forward revision and returns the JSON:API resource.
   *
   * @param \Drupal\node\NodeStorageInterface $storage
   *   Node storage.
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The route entity, used for the row lock.
   * @param \Drupal\node\NodeInterface $draft
   *   The translation being saved.
   * @param \Drupal\jsonapi\ResourceType\ResourceType $resource_type
   *   The resource type.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   * @param array<int, string> $versions
   *   Live and working revision ids checked before save.
   * @param bool $creating_translation
   *   TRUE when this save must leave the live revision without the new
   *   language.
   *
   * @return \Drupal\jsonapi\ResourceResponse
   *   The saved resource.
   */
  private function saveForwardRevision(NodeStorageInterface $storage, EntityInterface $entity, NodeInterface $draft, ResourceType $resource_type, Request $request, array $versions, bool $creating_translation = FALSE): ResourceResponse {
    $database = $this->draftDatabase;
    $transaction = $database->startTransaction();
    $langcode = $draft->language()->getId();
    try {
      // Serialize the save on the node's base row, then re-read both
      // revision pointers. Validation already ran outside this lock.
      $lock_query = $database->select('node', 'n');
      $lock_query->fields('n', ['nid']);
      $lock_query->condition('nid', $entity->id());
      $lock_query->forUpdate();
      $lock_query->execute()->fetchField();
      $stored_live = $storage->loadUnchanged($entity->id());
      $latest_id = $storage->getLatestRevisionId($entity->id());
      if ($creating_translation && $versions[2] === '') {
        $this->assertCreateRevisionPointers($stored_live, $latest_id, $versions);
      }
      else {
        $this->assertRevisionPointers($stored_live, $latest_id, $versions);
      }
      if ($creating_translation) {
        $current = $versions[2] === '' ? $stored_live : $storage->loadRevision($latest_id);
        if ($current instanceof NodeInterface && $current->hasTranslation($langcode)) {
          throw new ConflictHttpException('A translation for this language already exists. Continue it instead of creating it.');
        }
      }
      $draft->setNewRevision(TRUE);
      $draft->isDefaultRevision(FALSE);
      $draft->setRevisionUserId($this->user->id());
      $draft->setRevisionCreationTime($this->time->getRequestTime());
      $draft->save();
      $stored_live = $storage->loadUnchanged($entity->id());
      if (!$stored_live instanceof NodeInterface
        || (string) $stored_live->getRevisionId() !== $versions[1]
        || $draft->isPublished() || $draft->isDefaultRevision()) {
        throw new ConflictHttpException('Draft continuation changed the live revision; the save was rolled back.');
      }
      if ($creating_translation && $stored_live->hasTranslation($langcode)) {
        throw new ConflictHttpException('Draft continuation changed the live revision; the save was rolled back.');
      }
      $primary_data = new ResourceObjectData([ResourceObject::createFromEntity($resource_type, $draft)], 1);
      /** @var \Drupal\jsonapi\JsonApiResource\IncludedData $includes */
      $includes = $this->getIncludes($request, $primary_data);
      return $this->buildWrappedResponse($primary_data, $request, $includes);
    }
    catch (\Throwable $exception) {
      $transaction->rollBack();
      throw $exception;
    }
  }

  /**
   * Refuses a request whose live or working revision no longer matches.
   *
   * @param \Drupal\Core\Entity\EntityInterface|null $live
   *   The stored default revision, or NULL if the node disappeared.
   * @param int|string|null $latest_id
   *   The stored latest revision id.
   * @param array<int, string> $versions
   *   Preg-match captures: [1] live id, [2] working id.
   *
   * @return \Drupal\node\NodeInterface
   *   The stored default revision.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\ConflictHttpException
   *   When the stored pointers no longer match the request.
   */
  private function assertRevisionPointers(?EntityInterface $live, int|string|null $latest_id, array $versions): NodeInterface {
    if (!$live instanceof NodeInterface
      || (string) $live->getRevisionId() !== $versions[1]
      || (string) $latest_id !== $versions[2]
      || $versions[1] === $versions[2]) {
      throw new ConflictHttpException('The live or working revision changed. Reload before retrying.');
    }
    return $live;
  }

  /**
   * Validates create-translation revision pointers.
   *
   * @param \Drupal\Core\Entity\EntityInterface|null $live
   *   The stored default revision.
   * @param int|string|null $latest_id
   *   The stored latest revision id.
   * @param array<int, string> $versions
   *   Live and optional working ids.
   */
  private function assertCreateRevisionPointers(?EntityInterface $live, int|string|null $latest_id, array $versions): void {
    if (!$live instanceof NodeInterface || (string) $live->getRevisionId() !== $versions[1]) {
      throw new ConflictHttpException('The live or working revision changed. Reload before retrying.');
    }
    if ($versions[2] === '') {
      if ((string) $latest_id !== $versions[1]) {
        throw new ConflictHttpException('A working revision exists. Reload and send both revision IDs.');
      }
      return;
    }
    if ((string) $latest_id !== $versions[2] || $versions[1] === $versions[2]) {
      throw new ConflictHttpException('The live or working revision changed. Reload before retrying.');
    }
  }

  /**
   * Loads the unpublished forward revision named by the working pointer.
   *
   * @param \Drupal\node\NodeStorageInterface $storage
   *   Node storage.
   * @param \Drupal\node\NodeInterface $entity
   *   The canonical node from the route.
   * @param string $latest_id
   *   The working revision id already checked against If-Match.
   * @param string|null $langcode
   *   The translation to return, or NULL for single-language drafts.
   *
   * @return \Drupal\node\NodeInterface
   *   The unpublished non-default revision, in the requested language.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\ConflictHttpException
   *   When the named revision is not an unpublished forward draft.
   */
  private function loadWorkingDraft(NodeStorageInterface $storage, NodeInterface $entity, string $latest_id, ?string $langcode): NodeInterface {
    $draft = $storage->loadRevision($latest_id);
    if (!$draft instanceof NodeInterface || $draft->isDefaultRevision()
      || $draft->bundle() !== $entity->bundle()
      || $draft->uuid() !== $entity->uuid()) {
      throw new ConflictHttpException('The target is not an unpublished forward revision.');
    }
    $languages = $draft->getTranslationLanguages();
    if ($langcode === NULL) {
      if (count($languages) !== 1) {
        throw new ConflictHttpException('Translated draft continuation requires X-MCP-Draft-Langcode.');
      }
      if ($draft->isPublished()) {
        throw new ConflictHttpException('The target is not an unpublished forward revision.');
      }
      return $draft;
    }
    if (!$draft->hasTranslation($langcode)) {
      throw new ConflictHttpException('The working revision has no translation for the requested language.');
    }
    $translation = $draft->getTranslation($langcode);
    if ($translation->isPublished()) {
      throw new ConflictHttpException('The requested translation is not an unpublished working draft.');
    }
    return $translation;
  }

  /**
   * Loads the revision a create-translation write will extend.
   *
   * @param \Drupal\node\NodeStorageInterface $storage
   *   Node storage.
   * @param \Drupal\node\NodeInterface $live
   *   The live default revision.
   * @param array<int, string> $versions
   *   Live and optional working ids.
   * @param int|string|null $latest_id
   *   The stored latest revision id.
   *
   * @return \Drupal\node\NodeInterface
   *   The live revision or the unpublished working revision.
   */
  private function loadCreateBase(NodeStorageInterface $storage, NodeInterface $live, array $versions, int|string|null $latest_id): NodeInterface {
    if ($versions[2] === '') {
      return $live;
    }
    $working = $storage->loadRevision($versions[2]);
    if (!$working instanceof NodeInterface || $working->isPublished()
      || $working->isDefaultRevision() || $working->uuid() !== $live->uuid()
      || (string) $latest_id !== $versions[2]) {
      throw new ConflictHttpException('The target is not an unpublished forward revision.');
    }
    return $working;
  }

  /**
   * Copies live translations onto the working entity.
   *
   * Prevents a save from dropping translations that exist only on the
   * default revision.
   *
   * @param \Drupal\node\NodeInterface $draft
   *   The revision being extended.
   * @param \Drupal\node\NodeInterface $live
   *   The live default revision.
   *
   * @see https://www.drupal.org/project/drupal/issues/3329066
   */
  private function mergeDefaultTranslations(NodeInterface $draft, NodeInterface $live): void {
    foreach ($live->getTranslationLanguages() as $language) {
      $langcode = $language->getId();
      if ($draft->hasTranslation($langcode)) {
        continue;
      }
      $existing = $live->getTranslation($langcode);
      $draft->addTranslation($langcode, $existing->toArray());
      $added = $draft->getTranslation($langcode);
      $added->setRevisionTranslationAffected(FALSE);
    }
  }

  /**
   * Sets translation metadata when the content_translation manager is present.
   *
   * @param \Drupal\node\NodeInterface $translation
   *   The new translation.
   * @param string $source_langcode
   *   The source language.
   */
  private function applyTranslationMetadata(NodeInterface $translation, string $source_langcode): void {
    if (!is_object($this->translationManager)
      || !method_exists($this->translationManager, 'getTranslationMetadata')) {
      return;
    }
    $metadata = $this->translationManager->getTranslationMetadata($translation);
    $account = $this->entityTypeManager->getStorage('user')->load($this->user->id());
    if ($account instanceof UserInterface) {
      $metadata->setAuthor($account);
    }
    $metadata->setSource($source_langcode);
    $metadata->setCreatedTime($this->time->getRequestTime());
  }

  /**
   * Refuses a translation whose moderation state is a default revision.
   *
   * Saving through a published translation would let content_moderation promote
   * the working revision to the live default.
   *
   * @param \Drupal\node\NodeInterface $draft
   *   The translation about to be saved.
   */
  private function assertTranslationNotDefaultRevisionState(NodeInterface $draft): void {
    if (!$draft->hasField('moderation_state')) {
      return;
    }
    $moderation = $this->draftModeration;
    if (!$moderation || !$moderation->isModeratedEntity($draft)) {
      return;
    }
    $state_id = $draft->get('moderation_state')->value;
    if (!is_string($state_id) || $state_id === '') {
      return;
    }
    $state = $moderation->getWorkflowForEntity($draft)->getTypePlugin()->getState($state_id);
    if ($state instanceof ContentModerationState && $state->isDefaultRevisionState()) {
      throw new ConflictHttpException('The requested translation is not an unpublished working draft.');
    }
  }

  /**
   * Copies submitted JSON:API fields onto the working revision or translation.
   *
   * @param \Drupal\jsonapi\ResourceType\ResourceType $resource_type
   *   The node resource type.
   * @param \Drupal\node\NodeInterface $parsed
   *   The deserialized request entity.
   * @param \Drupal\node\NodeInterface $draft
   *   The working revision or translation being continued.
   * @param \Drupal\node\NodeInterface $live
   *   The live default revision, used to refuse alias changes.
   * @param array<string, mixed> $data
   *   The JSON:API `data` document.
   * @param bool $translation_write
   *   TRUE when the write must not retarget shared structure or files.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
   *   When the payload would change an alias or a non-revisionable field.
   */
  private function applySubmittedDraftFields(ResourceType $resource_type, NodeInterface $parsed, NodeInterface $draft, NodeInterface $live, array $data, bool $translation_write = FALSE): void {
    $fields = array_unique(array_merge(array_keys($data['attributes'] ?? []), array_keys($data['relationships'] ?? [])));
    foreach ($fields as $public_name) {
      $name = $resource_type->getInternalName($public_name);
      if (in_array($name, self::SKIP_FIELD_NAMES, TRUE)) {
        continue;
      }
      // Aliases are not revisioned. The connector may round-trip the live
      // alias, but a draft save must never create or rename a public alias.
      if ($name === 'path') {
        if ($parsed->get('path')->alias !== $live->get('path')->alias) {
          throw new BadRequestHttpException('A draft continuation cannot change the public alias.');
        }
        continue;
      }
      if (!$draft->hasField($name) || !$parsed->hasField($name)) {
        continue;
      }
      $definition = $draft->getFieldDefinition($name);
      if ($translation_write) {
        $type = $definition->getType();
        if ($type === 'entity_reference_revisions') {
          if (!$draft->get($name)->equals($parsed->get($name))) {
            throw new BadRequestHttpException('Paragraph structure is shared and cannot be changed on a translation draft.');
          }
          continue;
        }
        if (in_array($type, ['image', 'file'], TRUE)) {
          $current_ids = array_column($draft->get($name)->getValue(), 'target_id');
          $incoming_ids = array_column($parsed->get($name)->getValue(), 'target_id');
          if ($current_ids !== $incoming_ids) {
            throw new BadRequestHttpException('A translation cannot replace a file or image reference.');
          }
        }
        if ($type === 'entity_reference' && !$definition->isTranslatable()
          && !$draft->get($name)->equals($parsed->get($name))) {
          throw new BadRequestHttpException('Shared references cannot be changed on a translation draft.');
        }
        if (!$definition->isTranslatable() && $name !== 'moderation_state'
          && !$draft->get($name)->equals($parsed->get($name))) {
          throw new BadRequestHttpException('Untranslatable fields cannot be changed on a translation draft.');
        }
      }
      if ($name !== 'moderation_state' && !$definition->getFieldStorageDefinition()->isRevisionable()
        && !$draft->get($name)->equals($parsed->get($name))) {
        throw new BadRequestHttpException('A draft continuation cannot change non-revisionable fields.');
      }
      $this->updateEntityField($resource_type, $parsed, $draft, $public_name);
    }
  }

  /**
   * Compact translation list for one revision.
   *
   * @param \Drupal\node\NodeInterface $node
   *   A revision.
   *
   * @return array{vid: string, translations: list<array<string, mixed>>}
   *   Revision id and per-language status.
   */
  private function summarizeRevisionTranslations(NodeInterface $node): array {
    $default = $node->getUntranslated()->language()->getId();
    $translations = [];
    foreach ($node->getTranslationLanguages() as $language) {
      $langcode = $language->getId();
      $translation = $node->getTranslation($langcode);
      $row = [
        'langcode' => $langcode,
        'default' => $langcode === $default,
        'status' => $translation->isPublished(),
        'title' => $translation->label(),
      ];
      if ($translation->hasField('moderation_state')) {
        $row['moderation_state'] = $translation->get('moderation_state')->value;
      }
      $translations[] = $row;
    }
    return [
      'vid' => (string) $node->getRevisionId(),
      'translations' => $translations,
    ];
  }

  /**
   * Refuses a continuation that would publish or become the default revision.
   *
   * @param \Drupal\node\NodeInterface $draft
   *   The working revision after submitted fields were applied.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException
   *   When the continuation would publish or become the default revision.
   */
  private function assertDraftRemainsUnpublished(NodeInterface $draft): void {
    // Field updates above may have changed the previously checked status.
    // @phpstan-ignore if.alwaysFalse (The entity is mutable through updateEntityField.)
    if ($draft->isPublished()) {
      throw new AccessDeniedHttpException('Draft continuation cannot publish content.');
    }
    if ($draft->hasField('moderation_state')) {
      $moderation = $this->draftModeration;
      if ($moderation && $moderation->isModeratedEntity($draft)) {
        $state = $moderation->getWorkflowForEntity($draft)->getTypePlugin()
          ->getState($draft->get('moderation_state')->value);
        if (!$state instanceof ContentModerationState || $state->isPublishedState() || $state->isDefaultRevisionState()) {
          throw new AccessDeniedHttpException('Draft continuation requires a non-default unpublished moderation state.');
        }
      }
    }
  }

}
