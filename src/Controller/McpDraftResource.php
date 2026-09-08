<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Component\Serialization\Json;
use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityInterface;
use Drupal\jsonapi\Controller\EntityResource;
use Drupal\jsonapi\JsonApiResource\JsonApiDocumentTopLevel;
use Drupal\jsonapi\JsonApiResource\ResourceObject;
use Drupal\jsonapi\JsonApiResource\ResourceObjectData;
use Drupal\jsonapi\ResourceType\ResourceType;
use Drupal\jsonapi\ResourceResponse;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\node\NodeInterface;
use Drupal\node\NodeStorageInterface;
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
 * @phpstan-ignore classExtendsInternalClass.classExtendsInternalClass (Core adapter verified across the supported Drupal matrix.)
 */
final class McpDraftResource extends EntityResource {

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
   * Injects draft services without duplicating core's controller constructor.
   */
  public function setDraftServices(Connection $database, McpPolicyResolver $policy, ?ModerationInformationInterface $moderation): void {
    $this->draftDatabase = $database;
    $this->draftPolicy = $policy;
    $this->draftModeration = $moderation;
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
   * @return \Drupal\jsonapi\ResourceResponse|\Symfony\Component\HttpFoundation\JsonResponse
   *   The saved resource or preflight metadata.
   */
  public function patchIndividual(ResourceType $resource_type, EntityInterface $entity, Request $request): ResourceResponse|JsonResponse {
    if (!$entity instanceof NodeInterface
      || !$this->draftPolicy->isGoverned()) {
      throw new AccessDeniedHttpException('Draft continuation requires a governed node update.');
    }
    $match = $request->headers->get('If-Match', '');
    if (!preg_match('/^"([1-9][0-9]*):([1-9][0-9]*)"$/D', $match, $versions)) {
      throw new BadRequestHttpException('If-Match must identify the live and working revision IDs as "live:working".');
    }
    $preflight = $request->headers->get('X-MCP-Draft-Preflight', '0');
    if (!in_array($preflight, ['0', '1'], TRUE)) {
      throw new BadRequestHttpException('X-MCP-Draft-Preflight must be 0 or 1.');
    }
    /** @var \Drupal\node\NodeStorageInterface $storage */
    $storage = $this->entityTypeManager->getStorage('node');
    $live = $this->assertRevisionPointers(
      $storage->loadUnchanged($entity->id()),
      $storage->getLatestRevisionId($entity->id()),
      $versions,
    );
    $draft = $this->loadWorkingDraft($storage, $entity, $versions[2]);
    if (!$draft->access('update', $this->user)) {
      throw new AccessDeniedHttpException('Draft update access denied.');
    }
    // Core's deserialize() docblock says array, but this normalizer returns
    // the content entity. Keep the actual contract explicit here.
    /** @var \Drupal\node\NodeInterface $parsed */
    $parsed = $this->deserialize($resource_type, $request, JsonApiDocumentTopLevel::class);
    $data = Json::decode($request->getContent())['data'];
    if (($data['id'] ?? NULL) !== $draft->uuid()) {
      throw new BadRequestHttpException('The selected entity does not match the ID in the payload.');
    }
    $this->applySubmittedDraftFields($resource_type, $parsed, $draft, $live, $data);
    $this->assertDraftRemainsUnpublished($draft);
    // Include entity-level governance constraints, not only changed fields.
    static::validate($draft);
    if ($preflight === '1') {
      return new JsonResponse([
        'meta' => [
          'draft_preflight' => TRUE,
          'live' => $versions[1],
          'working' => $versions[2],
        ],
      ], 200, ['Cache-Control' => 'no-store']);
    }

    $database = $this->draftDatabase;
    $transaction = $database->startTransaction();
    try {
      // Serialize the save on the node's base row, then re-read both
      // revision pointers. Validation already ran outside this lock.
      $lock_query = $database->select('node', 'n');
      $lock_query->fields('n', ['nid']);
      $lock_query->condition('nid', $entity->id());
      $lock_query->forUpdate();
      $lock_query->execute()->fetchField();
      $this->assertRevisionPointers(
        $storage->loadUnchanged($entity->id()),
        $storage->getLatestRevisionId($entity->id()),
        $versions,
      );
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
   * Loads the unpublished forward revision named by the working pointer.
   *
   * @param \Drupal\node\NodeStorageInterface $storage
   *   Node storage.
   * @param \Drupal\node\NodeInterface $entity
   *   The canonical node from the route.
   * @param string $latest_id
   *   The working revision id already checked against If-Match.
   *
   * @return \Drupal\node\NodeInterface
   *   The unpublished non-default revision.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\ConflictHttpException
   *   When the named revision is not an unpublished forward draft.
   */
  private function loadWorkingDraft(NodeStorageInterface $storage, NodeInterface $entity, string $latest_id): NodeInterface {
    $draft = $storage->loadRevision($latest_id);
    if (!$draft instanceof NodeInterface || $draft->isPublished()
      || $draft->isDefaultRevision() || $draft->bundle() !== $entity->bundle()
      || $draft->uuid() !== $entity->uuid()) {
      throw new ConflictHttpException('The target is not an unpublished forward revision.');
    }
    // Multilingual continuation needs a translation-specific precondition;
    // refuse it until that contract is implemented, rather than guessing.
    if (count($draft->getTranslationLanguages()) !== 1) {
      throw new ConflictHttpException('Translated draft continuation is not supported.');
    }
    return $draft;
  }

  /**
   * Copies submitted JSON:API fields onto the working revision.
   *
   * @param \Drupal\jsonapi\ResourceType\ResourceType $resource_type
   *   The node resource type.
   * @param \Drupal\node\NodeInterface $parsed
   *   The deserialized request entity.
   * @param \Drupal\node\NodeInterface $draft
   *   The working revision being continued.
   * @param \Drupal\node\NodeInterface $live
   *   The live default revision, used to refuse alias changes.
   * @param array<string, mixed> $data
   *   The JSON:API `data` document.
   *
   * @throws \Symfony\Component\HttpKernel\Exception\BadRequestHttpException
   *   When the payload would change an alias or a non-revisionable field.
   */
  private function applySubmittedDraftFields(ResourceType $resource_type, NodeInterface $parsed, NodeInterface $draft, NodeInterface $live, array $data): void {
    $fields = array_unique(array_merge(array_keys($data['attributes'] ?? []), array_keys($data['relationships'] ?? [])));
    foreach ($fields as $public_name) {
      $name = $resource_type->getInternalName($public_name);
      // Aliases are not revisioned. The connector may round-trip the live
      // alias, but a draft save must never create or rename a public alias.
      if ($name === 'path') {
        if ($parsed->get('path')->alias !== $live->get('path')->alias) {
          throw new BadRequestHttpException('A draft continuation cannot change the public alias.');
        }
        continue;
      }
      if ($name !== 'moderation_state' && !$draft->getFieldDefinition($name)->getFieldStorageDefinition()->isRevisionable()
        && !$draft->get($name)->equals($parsed->get($name))) {
        throw new BadRequestHttpException('A draft continuation cannot change non-revisionable fields.');
      }
      $this->updateEntityField($resource_type, $parsed, $draft, $public_name);
    }
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
