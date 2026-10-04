<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Draft;

use Drupal\Component\Plugin\Exception\PluginNotFoundException;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Drupal\Core\Field\FieldItemInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\jsonapi\JsonApiResource\JsonApiDocumentTopLevel;
use Drupal\jsonapi\ResourceType\ResourceType;
use Drupal\jsonapi\ResourceType\ResourceTypeRepositoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;

/**
 * Plans one atomic nested paragraph replacement for a node draft.
 *
 * The published host keeps its pins. A new unpublished parent is built in
 * memory, validated, and saved only with the host draft. Kept children are
 * referenced by the revision the published parent already pins. They are not
 * loaded onto that new parent as editable entities during planning.
 */
final class McpNestedReplacement {

  /**
   * Inventory and preflight name.
   */
  public const OPERATION = 'nested_replacement';

  /**
   * Top-level meta key. One object, not a list.
   */
  public const META_KEY = 'mcp_nested_replacement';

  /**
   * Client attributes that must not be written onto a new paragraph.
   *
   * @var list<string>
   */
  private const LOCKED_FIELDS = [
    'status',
    'langcode',
    'default_langcode',
    'parent_id',
    'parent_type',
    'parent_field_name',
    'behavior_settings',
    'revision_translation_affected',
    'revision_default',
    'created',
    'changed',
    'vid',
    'nid',
    'mid',
    'id',
    'revision_id',
    'uuid',
    'type',
    'uid',
    'revision_uid',
    'moderation_state',
  ];

  /**
   * Fields copied from the published parent except the child list.
   *
   * Bookkeeping stays behind so the new paragraph gets its own identity.
   *
   * @var list<string>
   */
  private const SKIP_COPY = [
    'status',
    'langcode',
    'default_langcode',
    'parent_id',
    'parent_type',
    'parent_field_name',
    'revision_translation_affected',
    'revision_default',
    'vid',
    'nid',
    'mid',
    'id',
    'revision_id',
    'uuid',
    'type',
    'uid',
    'revision_uid',
    'moderation_state',
  ];

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  private EntityTypeManagerInterface $entityTypeManager;

  /**
   * The JSON:API resource type repository.
   *
   * @var \Drupal\jsonapi\ResourceType\ResourceTypeRepositoryInterface
   */
  private ResourceTypeRepositoryInterface $resourceTypes;

  /**
   * The JSON:API denormalizer.
   *
   * @var \Symfony\Component\Serializer\Normalizer\DenormalizerInterface
   */
  private DenormalizerInterface $serializer;

  /**
   * The acting account.
   *
   * @var \Drupal\Core\Session\AccountInterface
   */
  private AccountInterface $account;

  /**
   * The language manager.
   *
   * @var \Drupal\Core\Language\LanguageManagerInterface
   */
  private LanguageManagerInterface $languageManager;

  /**
   * Constructs the planner.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\jsonapi\ResourceType\ResourceTypeRepositoryInterface $resource_types
   *   The resource type repository.
   * @param \Symfony\Component\Serializer\Normalizer\DenormalizerInterface $serializer
   *   The JSON:API denormalizer.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The acting account.
   * @param \Drupal\Core\Language\LanguageManagerInterface $language_manager
   *   The language manager.
   */
  public function __construct(EntityTypeManagerInterface $entity_type_manager, ResourceTypeRepositoryInterface $resource_types, DenormalizerInterface $serializer, AccountInterface $account, LanguageManagerInterface $language_manager) {
    $this->entityTypeManager = $entity_type_manager;
    $this->resourceTypes = $resource_types;
    $this->serializer = $serializer;
    $this->account = $account;
    $this->languageManager = $language_manager;
  }

  /**
   * Validates one nested replacement and builds its unsaved paragraphs.
   *
   * Returns NULL when the request does not ask for a nested replacement.
   * Nothing in this method is saved. Invalid input says that no write was
   * attempted.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $published
   *   The published default revision.
   * @param \Drupal\Core\Entity\ContentEntityInterface $draft
   *   The draft the request will save.
   * @param list<array<string, mixed>> $components
   *   Direct component entries, which cannot be combined with this operation.
   * @param array<string, mixed> $data
   *   The JSON:API data document.
   * @param \Drupal\jsonapi\ResourceType\ResourceType $host_resource_type
   *   The host resource type.
   * @param bool $translation_write
   *   TRUE when the request writes a non-default language.
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return \Drupal\mcp_sentinel\Draft\McpNestedReplacementPlan|null
   *   The plan, or NULL when the meta key is absent.
   */
  public function plan(ContentEntityInterface $published, ContentEntityInterface $draft, array $components, array $data, ResourceType $host_resource_type, bool $translation_write, Request $request): ?McpNestedReplacementPlan {
    $spec = $this->readSpec($request);
    if ($spec === NULL) {
      return NULL;
    }
    if ($published->getEntityTypeId() !== 'node') {
      $this->deny('Nested replacement is supported on nodes only.');
    }
    if ($translation_write) {
      $this->deny('Nested replacement is supported on the default language only.');
    }
    if ($components !== []) {
      $this->deny('A request cannot combine component changes with a nested replacement.');
    }
    $field_name = $this->resolveFieldName($published, $host_resource_type, (string) $spec['field']);
    $child_field = (string) $spec['childField'];
    $this->assertReferenceField($published, $field_name);
    $this->assertNoHostRelationship($data, $host_resource_type, $field_name);
    $published_host = $published->getUntranslated();
    $draft_host = $draft->getUntranslated();
    $this->assertPins($published_host, $field_name);
    $this->assertPins($draft_host, $field_name);
    if (count($published_host->get($field_name)) !== count($draft_host->get($field_name))) {
      $this->deny('A forward draft already replaces this component. Reload before retrying.', 409, FALSE);
    }
    $parent = $this->findPublishedParent($published_host, $field_name, $spec['parent']);
    $this->assertSameSlot($draft_host, $field_name, $parent['delta'], $parent['uuid']);
    $this->refuseLibrary($parent['entity']);
    if (!$parent['entity']->hasField($child_field)) {
      $this->deny(sprintf('The published component has no field %s.', $child_field));
    }
    $this->assertReferenceField($parent['entity'], $child_field);
    $this->assertPins($parent['entity'], $child_field);
    $requested = $spec['children'];
    if (!is_array($requested)) {
      $this->deny('children must be the new child list.');
    }
    $children = $this->buildChildren($parent['entity'], $child_field, $requested);
    $watched = $this->watchPublished($parent['entity'], $child_field);
    $new_parent = $this->buildParent($parent['entity'], $child_field, $children);
    return new McpNestedReplacementPlan(
      $this->entityTypeManager,
      $field_name,
      $parent['delta'],
      $new_parent,
      (string) $published_host->id(),
      (string) $published_host->getRevisionId(),
      $this->pinKeys($published_host, $field_name),
      $watched,
    );
  }

  /**
   * Reads the nested replacement object from the request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return array<string, mixed>|null
   *   The spec, or NULL when the key is absent.
   */
  private function readSpec(Request $request): ?array {
    $document = json_decode($request->getContent(), TRUE);
    if (!is_array($document) || !isset($document['meta']) || !is_array($document['meta'])
      || !array_key_exists(self::META_KEY, $document['meta'])) {
      return NULL;
    }
    $spec = $document['meta'][self::META_KEY];
    if (!is_array($spec) || array_is_list($spec)) {
      $this->deny('meta.mcp_nested_replacement must be one replacement.');
    }
    foreach (['field', 'parent', 'childField', 'children'] as $key) {
      if (!array_key_exists($key, $spec)) {
        $this->deny('A nested replacement needs field, parent, childField, and children.');
      }
    }
    if (!is_string($spec['field']) || !is_string($spec['parent']) || !is_string($spec['childField'])
      || $spec['field'] === '' || $spec['parent'] === '' || $spec['childField'] === '') {
      $this->deny('A nested replacement needs field, parent, childField, and children.');
    }
    if (!is_array($spec['children']) || !array_is_list($spec['children'])) {
      $this->deny('children must be the new child list.');
    }
    return $spec;
  }

  /**
   * Maps a public field name onto the host.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $host
   *   The published host.
   * @param \Drupal\jsonapi\ResourceType\ResourceType $resource_type
   *   The host resource type.
   * @param string $public_name
   *   The field name from the request.
   *
   * @return string
   *   The internal field name.
   */
  private function resolveFieldName(ContentEntityInterface $host, ResourceType $resource_type, string $public_name): string {
    $internal = $resource_type->getInternalName($public_name);
    if ($host->hasField($internal)) {
      return $internal;
    }
    if ($host->hasField($public_name)) {
      return $public_name;
    }
    $this->deny(sprintf('The host has no field %s.', $public_name));
  }

  /**
   * Refuses a translatable or non-paragraph reference field.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The host or parent paragraph.
   * @param string $field_name
   *   The field name.
   */
  private function assertReferenceField(ContentEntityInterface $entity, string $field_name): void {
    if (!$entity->hasField($field_name)) {
      $this->deny(sprintf('Field %s is not a paragraph reference.', $field_name));
    }
    $definition = $entity->getFieldDefinition($field_name);
    $storage = $definition->getFieldStorageDefinition();
    if ($definition->getType() !== 'entity_reference_revisions'
      || $storage->getSetting('target_type') !== 'paragraph') {
      $this->deny(sprintf('Field %s is not a paragraph reference.', $field_name));
    }
    if ($definition->isTranslatable()) {
      $this->deny('Nested replacement needs an untranslatable paragraph reference field.');
    }
  }

  /**
   * Refuses a request that also changes the host paragraph field.
   *
   * @param array<string, mixed> $data
   *   The JSON:API data document.
   * @param \Drupal\jsonapi\ResourceType\ResourceType $resource_type
   *   The host resource type.
   * @param string $field_name
   *   The internal field name.
   */
  private function assertNoHostRelationship(array $data, ResourceType $resource_type, string $field_name): void {
    $relationships = is_array($data['relationships'] ?? NULL) ? $data['relationships'] : [];
    foreach (array_keys($relationships) as $public_name) {
      if ($resource_type->getInternalName((string) $public_name) === $field_name || $public_name === $field_name) {
        $this->deny('A request cannot change a paragraph field and replace a nested paragraph together.');
      }
    }
  }

  /**
   * Refuses a paragraph reference list with a missing revision id.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity that holds the pins.
   * @param string $field_name
   *   The reference field.
   */
  private function assertPins(ContentEntityInterface $entity, string $field_name): void {
    foreach ($entity->get($field_name) as $item) {
      $target_id = self::pinValue($item, 'target_id');
      $revision_id = self::pinValue($item, 'target_revision_id');
      if (!$this->isFiniteId($target_id) || !$this->isFiniteId($revision_id)) {
        $this->deny('A paragraph pin is missing its revision.');
      }
    }
  }

  /**
   * Finds the published parent pin by UUID.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $host
   *   The published host.
   * @param string $field_name
   *   The host field.
   * @param string $uuid
   *   The parent UUID.
   *
   * @return array{delta: int, uuid: string, entity: \Drupal\Core\Entity\ContentEntityInterface}
   *   The slot and the published paragraph revision.
   */
  private function findPublishedParent(ContentEntityInterface $host, string $field_name, string $uuid): array {
    $found = [];
    foreach ($host->get($field_name) as $delta => $item) {
      $paragraph = $this->loadParagraph((int) self::pinValue($item, 'target_revision_id'));
      if (!$paragraph instanceof ContentEntityInterface) {
        $this->deny('A paragraph pin is missing its revision.');
      }
      if (strcasecmp((string) $paragraph->uuid(), $uuid) === 0) {
        $found[] = [
          'delta' => (int) $delta,
          'uuid' => (string) $paragraph->uuid(),
          'entity' => $paragraph,
        ];
      }
    }
    if (count($found) !== 1) {
      $this->deny(sprintf('Parent %s is not a single paragraph referenced directly by the published host.', $uuid));
    }
    return $found[0];
  }

  /**
   * Refuses a working copy that already swapped this slot.
   *
   * The same paragraph UUID with a newer revision is still replaceable,
   * because the published host still pins the original.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $draft
   *   The draft host.
   * @param string $field_name
   *   The host field.
   * @param int $delta
   *   The published slot.
   * @param string $uuid
   *   The published parent UUID.
   */
  private function assertSameSlot(ContentEntityInterface $draft, string $field_name, int $delta, string $uuid): void {
    $item = $draft->get($field_name)->get($delta);
    $revision_id = $item instanceof FieldItemInterface ? self::pinValue($item, 'target_revision_id') : NULL;
    if (!$this->isFiniteId($revision_id)) {
      $this->deny('A paragraph pin is missing its revision.');
    }
    $paragraph = $this->loadParagraph((int) $revision_id);
    if (!$paragraph instanceof ContentEntityInterface
      || strcasecmp((string) $paragraph->uuid(), $uuid) !== 0) {
      $this->deny('A forward draft already replaces this component. Reload before retrying.', 409, FALSE);
    }
  }

  /**
   * Refuses a reusable library item or from_library paragraph.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The paragraph to check.
   */
  private function refuseLibrary(ContentEntityInterface $paragraph): void {
    if ($paragraph->getEntityTypeId() === 'paragraphs_library_item'
      || $paragraph->bundle() === 'from_library') {
      $this->deny('A reusable library item is updated through its library item draft route.');
    }
  }

  /**
   * Builds the unsaved keep, replace, and insert children.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $parent
   *   The published parent.
   * @param string $child_field
   *   The child reference field.
   * @param list<mixed> $requested
   *   The requested child list.
   *
   * @return list<array<string, mixed>>
   *   Keep pins and unsaved replacement paragraphs.
   */
  private function buildChildren(ContentEntityInterface $parent, string $child_field, array $requested): array {
    $known = [];
    foreach ($parent->get($child_field) as $item) {
      $child = $this->loadParagraph((int) self::pinValue($item, 'target_revision_id'));
      if (!$child instanceof ContentEntityInterface) {
        $this->deny('A paragraph pin is missing its revision.');
      }
      $this->refuseLibrary($child);
      $known[strtolower((string) $child->uuid())] = [
        'id' => (string) $child->id(),
        'revision_id' => (string) $child->getRevisionId(),
        'entity' => $child,
      ];
    }
    $seen = [];
    $built = [];
    foreach ($requested as $index => $child) {
      $where = 'children[' . $index . ']';
      if (!is_array($child) || array_is_list($child)) {
        $this->deny($where . ' must be an object.');
      }
      if (array_key_exists('relationships', $child)) {
        $this->deny('A nested child cannot include references. Send attribute values only.');
      }
      $op = $child['op'] ?? NULL;
      if ($op !== 'keep' && $op !== 'replace' && $op !== 'insert') {
        $this->deny($where . '.op must be keep, replace, or insert.');
      }
      if ($op === 'insert') {
        $built[] = [
          'op' => 'insert',
          'entity' => $this->buildInsertedChild($child, $parent->language()->getId(), $where),
        ];
        continue;
      }
      $id = $child['id'] ?? NULL;
      if (!is_string($id) || $id === '') {
        $this->deny($where . '.id must be the existing child UUID.');
      }
      $key = strtolower($id);
      if (!isset($known[$key])) {
        $this->deny(sprintf('%s is not a child of this component.', $id));
      }
      if (isset($seen[$key])) {
        $this->deny(sprintf('%s is listed more than once.', $id));
      }
      $seen[$key] = TRUE;
      if ($op === 'keep') {
        $built[] = [
          'op' => 'keep',
          'target_id' => $known[$key]['id'],
          'target_revision_id' => $known[$key]['revision_id'],
        ];
        continue;
      }
      $built[] = [
        'op' => 'replace',
        'entity' => $this->buildReplacedChild($known[$key]['entity'], $child, $where),
      ];
    }
    return $built;
  }

  /**
   * Copies the published parent and attaches the new child list.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $parent
   *   The published parent.
   * @param string $child_field
   *   The child reference field.
   * @param list<array<string, mixed>> $children
   *   The built child list.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface
   *   The unsaved parent.
   */
  private function buildParent(ContentEntityInterface $parent, string $child_field, array $children): ContentEntityInterface {
    $storage = $this->paragraphStorage();
    $created = $storage->create([
      'type' => $parent->bundle(),
      'langcode' => $parent->language()->getId(),
    ]);
    if (!$created instanceof ContentEntityInterface) {
      $this->deny('The replacement paragraph could not be prepared.');
    }
    $this->copyContent($parent, $created, $child_field);
    $items = [];
    foreach ($children as $child) {
      if ($child['op'] === 'keep') {
        $items[] = [
          'target_id' => $child['target_id'],
          'target_revision_id' => $child['target_revision_id'],
        ];
        continue;
      }
      $entity = $child['entity'];
      if ($entity instanceof ContentEntityInterface) {
        $items[] = ['entity' => $entity];
      }
    }
    $created->set($child_field, $items);
    $this->unpublish($created);
    $this->assertCreatable($created);
    $this->validateNew($created);
    return $created;
  }

  /**
   * Creates an inserted child from submitted values only.
   *
   * @param array<string, mixed> $child
   *   The insert entry.
   * @param string $langcode
   *   The host default language.
   * @param string $where
   *   The list position, for errors.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface
   *   The unsaved paragraph.
   */
  private function buildInsertedChild(array $child, string $langcode, string $where): ContentEntityInterface {
    $bundle = $this->bundleFromType($child['type'] ?? NULL, $where);
    $this->refuseLibraryBundle($bundle);
    $attributes = $this->attributeMap($child, $where);
    $storage = $this->paragraphStorage();
    $created = $storage->create([
      'type' => $bundle,
      'langcode' => $langcode,
    ]);
    if (!$created instanceof ContentEntityInterface) {
      $this->deny('The replacement paragraph could not be prepared.');
    }
    $this->overlayAttributes($created, $bundle, $attributes, $where);
    $this->overlayTranslations($created, $bundle, $child['translations'] ?? [], $where);
    $this->unpublish($created);
    $this->assertCreatable($created);
    $this->validateNew($created);
    return $created;
  }

  /**
   * Copies an existing child, then overlays the submitted values.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $existing
   *   The published child revision.
   * @param array<string, mixed> $child
   *   The replace entry.
   * @param string $where
   *   The list position, for errors.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface
   *   The unsaved paragraph.
   */
  private function buildReplacedChild(ContentEntityInterface $existing, array $child, string $where): ContentEntityInterface {
    $bundle = $this->bundleFromType($child['type'] ?? NULL, $where);
    if ($bundle !== $existing->bundle()) {
      $this->deny(sprintf('Replacement %s must keep paragraph type %s.', $where, $existing->bundle()));
    }
    $this->refuseLibraryBundle($bundle);
    $attributes = $this->attributeMap($child, $where);
    $storage = $this->paragraphStorage();
    $created = $storage->create([
      'type' => $bundle,
      'langcode' => $existing->language()->getId(),
    ]);
    if (!$created instanceof ContentEntityInterface) {
      $this->deny('The replacement paragraph could not be prepared.');
    }
    $this->copyContent($existing, $created, '');
    $this->overlayAttributes($created, $bundle, $attributes, $where);
    $this->overlayTranslations($created, $bundle, $child['translations'] ?? [], $where);
    $this->unpublish($created);
    $this->assertCreatable($created);
    $this->validateNew($created);
    return $created;
  }

  /**
   * Copies revisionable content onto a new paragraph.
   *
   * Reference fields are copied as target ids so the published paragraphs
   * are not duplicated and are not saved from this copy.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $source
   *   The published paragraph.
   * @param \Drupal\Core\Entity\ContentEntityInterface $destination
   *   The new paragraph.
   * @param string $except_field
   *   A field to leave unset, usually the child list.
   */
  private function copyContent(ContentEntityInterface $source, ContentEntityInterface $destination, string $except_field): void {
    $default = $source->getUntranslated()->language()->getId();
    foreach ($source->getTranslationLanguages() as $language) {
      $langcode = $language->getId();
      $from = $source->getTranslation($langcode);
      if ($langcode === $default) {
        $to = $destination;
      }
      else {
        if (!$destination->hasTranslation($langcode)) {
          $destination->addTranslation($langcode);
        }
        $to = $destination->getTranslation($langcode);
      }
      foreach ($from->getFieldDefinitions() as $name => $definition) {
        if ($name === $except_field || $this->skipCopy($name) || $definition->isComputed()) {
          continue;
        }
        if ($langcode !== $default && !$definition->isTranslatable()) {
          continue;
        }
        if (!$to->hasField($name)) {
          continue;
        }
        $to->set($name, $this->storedValue($from->get($name)));
      }
    }
  }

  /**
   * Field values safe to copy onto a new paragraph.
   *
   * @param \Drupal\Core\Field\FieldItemListInterface $field
   *   The source field.
   *
   * @return array<int, array<string, mixed>>
   *   Stored values, without a loaded entity.
   */
  private function storedValue($field): array {
    $type = $field->getFieldDefinition()->getType();
    $values = [];
    foreach ($field as $item) {
      if ($type === 'entity_reference_revisions') {
        $target_id = self::pinValue($item, 'target_id');
        $revision_id = self::pinValue($item, 'target_revision_id');
        if (!$this->isFiniteId($target_id) || !$this->isFiniteId($revision_id)) {
          $this->deny('A paragraph pin is missing its revision.');
        }
        $values[] = [
          'target_id' => (string) $target_id,
          'target_revision_id' => (string) $revision_id,
        ];
        continue;
      }
      $value = $item->getValue();
      unset($value['entity']);
      $values[] = $value;
    }
    return $values;
  }

  /**
   * Applies default-language attributes onto a new paragraph.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The new paragraph.
   * @param string $bundle
   *   The paragraph bundle.
   * @param array<string, mixed> $attributes
   *   JSON:API attributes.
   * @param string $where
   *   The list position, for errors.
   */
  private function overlayAttributes(ContentEntityInterface $paragraph, string $bundle, array $attributes, string $where): void {
    if ($attributes === []) {
      return;
    }
    $resource_type = $this->paragraphResourceType($bundle);
    $parsed = $this->denormalizeParagraph($resource_type, $attributes);
    foreach (array_keys($attributes) as $public_name) {
      $name = $resource_type->getInternalName((string) $public_name);
      $this->assertWritableField($paragraph, (string) $public_name, $name, $where);
      $paragraph->set($name, $parsed->get($name)->getValue());
    }
  }

  /**
   * Applies submitted translations onto a new paragraph.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The new paragraph.
   * @param string $bundle
   *   The paragraph bundle.
   * @param mixed $translations
   *   The submitted translation list.
   * @param string $where
   *   The list position, for errors.
   */
  private function overlayTranslations(ContentEntityInterface $paragraph, string $bundle, mixed $translations, string $where): void {
    if ($translations === [] || $translations === NULL) {
      return;
    }
    if (!is_array($translations) || !array_is_list($translations)) {
      $this->deny($where . '.translations must be a list.');
    }
    $default = $paragraph->getUntranslated()->language()->getId();
    $resource_type = $this->paragraphResourceType($bundle);
    foreach ($translations as $index => $translation) {
      $label = $where . '.translations[' . $index . ']';
      if (!is_array($translation) || !is_string($translation['langcode'] ?? NULL)
        || !is_array($translation['attributes'] ?? NULL) || array_is_list($translation['attributes'])) {
        $this->deny($label . ' must have langcode and attributes.');
      }
      $langcode = $translation['langcode'];
      if ($langcode === $default) {
        $this->deny($label . ' must not repeat the default language. Send those values in attributes.');
      }
      if ($this->languageManager->getLanguage($langcode) === NULL) {
        $this->deny(sprintf('Language %s is not enabled.', $langcode));
      }
      if (!$paragraph->isTranslatable()) {
        $this->deny('This paragraph type cannot store translations.');
      }
      if (!$paragraph->hasTranslation($langcode)) {
        $paragraph->addTranslation($langcode);
      }
      $target = $paragraph->getTranslation($langcode);
      $parsed = $this->denormalizeParagraph($resource_type, $translation['attributes']);
      foreach (array_keys($translation['attributes']) as $public_name) {
        $name = $resource_type->getInternalName((string) $public_name);
        $this->assertWritableField($target, (string) $public_name, $name, $label);
        if (!$target->getFieldDefinition($name)->isTranslatable()) {
          $this->deny(sprintf('%s cannot set untranslatable field %s.', $label, $public_name));
        }
        $target->set($name, $parsed->get($name)->getValue());
      }
    }
  }

  /**
   * Requires attributes to be an object. An empty object is allowed.
   *
   * @param array<string, mixed> $child
   *   The child entry.
   * @param string $where
   *   The list position, for errors.
   *
   * @return array<string, mixed>
   *   The attributes.
   */
  private function attributeMap(array $child, string $where): array {
    if (!array_key_exists('attributes', $child)) {
      $this->deny($where . '.attributes must be the field values for the new paragraph.');
    }
    $attributes = $child['attributes'];
    if (!is_array($attributes) || array_is_list($attributes)) {
      $this->deny($where . '.attributes must be the field values for the new paragraph.');
    }
    return $attributes;
  }

  /**
   * Refuses bookkeeping fields and fields the account may not edit.
   *
   * Field edit access that is merely neutral is allowed. Paragraph create
   * access is neutral on a JSON request, and field access follows it.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The new paragraph.
   * @param string $public_name
   *   The attribute name.
   * @param string $name
   *   The internal field name.
   * @param string $where
   *   The list position, for errors.
   */
  private function assertWritableField(ContentEntityInterface $paragraph, string $public_name, string $name, string $where): void {
    if ($this->isLockedField($name)) {
      $this->deny(sprintf('Field %s cannot be changed in a nested replacement.', $public_name));
    }
    if (!$paragraph->hasField($name)) {
      $this->deny(sprintf('%s has no field %s.', $where, $public_name));
    }
    $access = $paragraph->get($name)->access('edit', $this->account, TRUE);
    if ($access->isForbidden()) {
      $this->deny(sprintf('Edit access to field %s was denied.', $public_name), 403);
    }
  }

  /**
   * Allows paragraph create unless access is explicitly forbidden.
   *
   * ParagraphAccessControlHandler::checkCreateAccess() returns neutral unless
   * the request format is html. Requiring isAllowed() would make nested
   * replacement impossible on a JSON /mcp-draft request. Neutral is allowed.
   * Forbidden is not.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The new paragraph.
   */
  private function assertCreatable(ContentEntityInterface $paragraph): void {
    $access = $paragraph->access('create', $this->account, TRUE);
    if ($access->isForbidden()) {
      $this->deny('Create access to the replacement paragraph was denied.', 403);
    }
  }

  /**
   * Validates a new paragraph and keeps the failure before any write.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The new paragraph.
   */
  private function validateNew(ContentEntityInterface $paragraph): void {
    $violations = $paragraph->validate();
    $violations->filterByFieldAccess();
    if (count($violations) === 0) {
      return;
    }
    $messages = [];
    foreach ($violations as $violation) {
      $messages[] = $violation->getPropertyPath() . ': ' . $violation->getMessage();
    }
    $this->deny(implode(' ', $messages));
  }

  /**
   * Unpublishes every translation of a new paragraph.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $paragraph
   *   The new paragraph.
   */
  private function unpublish(ContentEntityInterface $paragraph): void {
    foreach ($paragraph->getTranslationLanguages() as $language) {
      $translation = $paragraph->getTranslation($language->getId());
      if ($translation instanceof EntityPublishedInterface) {
        $translation->setUnpublished();
      }
      if ($translation->hasField('moderation_state')) {
        $translation->set('moderation_state', 'draft');
      }
    }
  }

  /**
   * Snapshots the published parent and every paragraph it currently pins.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $parent
   *   The published parent.
   * @param string $child_field
   *   The child reference field. Every paragraph reference is watched.
   *
   * @return list<array{id: string, revision_id: string, values: array<string, array<string, mixed>>}>
   *   Snapshots.
   */
  private function watchPublished(ContentEntityInterface $parent, string $child_field): array {
    if (!$parent->hasField($child_field)) {
      $this->deny(sprintf('The published component has no field %s.', $child_field));
    }
    $watched = [];
    $seen = [];
    $add = function (ContentEntityInterface $paragraph) use (&$watched, &$seen): void {
      $id = (string) $paragraph->id();
      $revision_id = (string) $paragraph->getRevisionId();
      $key = $id . '#' . $revision_id;
      if (isset($seen[$key])) {
        return;
      }
      $seen[$key] = TRUE;
      $watched[] = [
        'id' => $id,
        'revision_id' => $revision_id,
        'values' => McpNestedReplacementPlan::fieldValues($paragraph),
      ];
    };
    $add($parent);
    foreach ($parent->getFieldDefinitions() as $name => $definition) {
      if ($definition->getType() !== 'entity_reference_revisions'
        || $definition->getFieldStorageDefinition()->getSetting('target_type') !== 'paragraph') {
        continue;
      }
      foreach ($parent->get($name) as $item) {
        $revision_id = self::pinValue($item, 'target_revision_id');
        if (!$this->isFiniteId($revision_id)) {
          $this->deny('A paragraph pin is missing its revision.');
        }
        $target = $this->loadParagraph((int) $revision_id);
        if ($target instanceof ContentEntityInterface) {
          $add($target);
        }
      }
    }
    return $watched;
  }

  /**
   * Published host pin keys in field order.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $host
   *   The published host.
   * @param string $field_name
   *   The host field.
   *
   * @return list<string>
   *   uuid#revision keys.
   */
  private function pinKeys(ContentEntityInterface $host, string $field_name): array {
    $keys = [];
    foreach ($host->get($field_name) as $item) {
      $revision_id = self::pinValue($item, 'target_revision_id');
      $paragraph = $this->loadParagraph((int) $revision_id);
      $uuid = $paragraph instanceof ContentEntityInterface ? (string) $paragraph->uuid() : '';
      $keys[] = $uuid . '#' . $revision_id;
    }
    return $keys;
  }

  /**
   * Denormalizes paragraph attributes into an unsaved entity.
   *
   * @param \Drupal\jsonapi\ResourceType\ResourceType $resource_type
   *   The paragraph resource type.
   * @param array<string, mixed> $attributes
   *   JSON:API attributes.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface
   *   The denormalized paragraph. It is not saved.
   */
  private function denormalizeParagraph(ResourceType $resource_type, array $attributes): ContentEntityInterface {
    try {
      $parsed = $this->serializer->denormalize([
        'data' => [
          'type' => $resource_type->getTypeName(),
          'attributes' => $attributes,
        ],
      ], JsonApiDocumentTopLevel::class, 'api_json', [
        'resource_type' => $resource_type,
      ]);
    }
    catch (\Throwable $exception) {
      $this->deny('The nested paragraph attributes could not be read. ' . $exception->getMessage());
    }
    if (!$parsed instanceof ContentEntityInterface) {
      $this->deny('The nested paragraph attributes could not be read.');
    }
    return $parsed;
  }

  /**
   * Returns the JSON:API resource type for a paragraph bundle.
   *
   * @param string $bundle
   *   The paragraph bundle.
   *
   * @return \Drupal\jsonapi\ResourceType\ResourceType
   *   The resource type.
   */
  private function paragraphResourceType(string $bundle): ResourceType {
    $resource_type = $this->resourceTypes->getByTypeName('paragraph--' . $bundle);
    if ($resource_type === NULL || $resource_type->getEntityTypeId() !== 'paragraph') {
      $this->deny(sprintf('Paragraph type %s is not available.', $bundle));
    }
    return $resource_type;
  }

  /**
   * Resolves a paragraph type name or bundle id.
   *
   * @param mixed $type
   *   The submitted type.
   * @param string $where
   *   The list position, for errors.
   *
   * @return string
   *   The bundle id.
   */
  private function bundleFromType(mixed $type, string $where): string {
    if (!is_string($type) || $type === '') {
      $this->deny($where . '.type must name the paragraph bundle.');
    }
    if (str_contains($type, '--')) {
      $parts = explode('--', $type, 2);
      if ($parts[0] !== 'paragraph' || $parts[1] === '') {
        $this->deny($where . '.type must be a paragraph bundle.');
      }
      return $parts[1];
    }
    return $type;
  }

  /**
   * Refuses a from_library bundle before a paragraph is created.
   *
   * @param string $bundle
   *   The paragraph bundle.
   */
  private function refuseLibraryBundle(string $bundle): void {
    if ($bundle === 'from_library' || $bundle === 'paragraphs_library_item') {
      $this->deny('A reusable library item is updated through its library item draft route.');
    }
  }

  /**
   * Whether a field name is bookkeeping.
   *
   * @param string $name
   *   The internal field name.
   *
   * @return bool
   *   TRUE when the client must not set it.
   */
  private function isLockedField(string $name): bool {
    return in_array($name, self::LOCKED_FIELDS, TRUE) || str_starts_with($name, 'content_translation_');
  }

  /**
   * Whether a copied paragraph should skip a field.
   *
   * @param string $name
   *   The field name.
   *
   * @return bool
   *   TRUE when the field stays off the new paragraph.
   */
  private function skipCopy(string $name): bool {
    return in_array($name, self::SKIP_COPY, TRUE) || str_starts_with($name, 'content_translation_');
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

  /**
   * Whether a pin id is a positive integer.
   *
   * @param mixed $value
   *   The raw field value.
   *
   * @return bool
   *   TRUE for a finite positive id.
   */
  private function isFiniteId(mixed $value): bool {
    if (is_int($value)) {
      return $value > 0;
    }
    if (is_string($value) && ctype_digit($value)) {
      return (int) $value > 0;
    }
    return FALSE;
  }

  /**
   * Loads a paragraph revision without attaching it to a host field.
   *
   * @param int $revision_id
   *   The revision id.
   *
   * @return \Drupal\Core\Entity\ContentEntityInterface|null
   *   The revision, or NULL.
   */
  private function loadParagraph(int $revision_id): ?ContentEntityInterface {
    $storage = $this->paragraphStorage();
    if (!$storage instanceof RevisionableStorageInterface) {
      return NULL;
    }
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
    try {
      $storage = $this->entityTypeManager->getStorage('paragraph');
    }
    catch (PluginNotFoundException) {
      $this->deny('Nested replacement needs the Paragraphs module.');
    }
    if (!$storage instanceof RevisionableStorageInterface) {
      $this->deny('Paragraph storage is not revisionable.');
    }
    return $storage;
  }

  /**
   * Throws the refusal for a nested replacement that has not been saved.
   *
   * @param string $message
   *   The reason.
   * @param int $status
   *   The HTTP status.
   * @param bool $note
   *   Whether to append the no-write sentence. The forward-draft conflict
   *   keeps its own wording.
   *
   * @return never
   *   This method always throws.
   */
  private function deny(string $message, int $status = 400, bool $note = TRUE): never {
    if ($note && !str_contains($message, 'No write was attempted.')) {
      $message .= ' No write was attempted.';
    }
    if ($status === 409) {
      throw new ConflictHttpException($message);
    }
    if ($status === 403) {
      throw new AccessDeniedHttpException($message);
    }
    if ($status !== 400) {
      throw new HttpException($status, $message);
    }
    throw new BadRequestHttpException($message);
  }

}
