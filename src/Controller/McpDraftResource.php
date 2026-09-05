<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Component\Serialization\Json;
use Drupal\Core\Entity\EntityInterface;
use Drupal\jsonapi\Controller\EntityResource;
use Drupal\jsonapi\JsonApiResource\JsonApiDocumentTopLevel;
use Drupal\jsonapi\JsonApiResource\ResourceObject;
use Drupal\jsonapi\JsonApiResource\ResourceObjectData;
use Drupal\jsonapi\ResourceType\ResourceType;
use Drupal\node\NodeInterface;
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
 */
final class McpDraftResource extends EntityResource {

  /**
   * {@inheritdoc}
   */
  public function patchIndividual(ResourceType $resource_type, EntityInterface $entity, Request $request) {
    if (!$entity instanceof NodeInterface
      || !\Drupal::service('mcp_sentinel.policy_resolver')->isGoverned()) {
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
    $storage = $this->entityTypeManager->getStorage('node');
    $database = \Drupal::database();
    $transaction = $database->startTransaction();
    try {
      // Serialize draft continuations on the node's base row, then re-read
      // both revision pointers. The preflight never calls entity save.
      $database->select('node', 'n')->fields('n', ['nid'])
        ->condition('nid', $entity->id())->forUpdate()->execute()->fetchField();
      $live = $storage->loadUnchanged($entity->id());
      $latest_id = $storage->getLatestRevisionId($entity->id());
      if ((string) $live->getRevisionId() !== $versions[1]
        || (string) $latest_id !== $versions[2]
        || $versions[1] === $versions[2]) {
        throw new ConflictHttpException('The live or working revision changed. Reload before retrying.');
      }
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
      if (!$draft->access('update', $this->user)) {
        throw new AccessDeniedHttpException('Draft update access denied.');
      }
      $parsed = $this->deserialize($resource_type, $request, JsonApiDocumentTopLevel::class);
      $data = Json::decode($request->getContent())['data'];
      if (($data['id'] ?? NULL) !== $draft->uuid()) {
        throw new BadRequestHttpException('The selected entity does not match the ID in the payload.');
      }
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
      if ($draft->isPublished()) {
        throw new AccessDeniedHttpException('Draft continuation cannot publish content.');
      }
      if ($draft->hasField('moderation_state')) {
        $moderation = \Drupal::service('content_moderation.moderation_information');
        if ($moderation->isModeratedEntity($draft)) {
          $state = $moderation->getWorkflowForEntity($draft)->getTypePlugin()
            ->getState($draft->get('moderation_state')->value);
          if ($state->isPublishedState() || $state->isDefaultRevisionState()) {
            throw new AccessDeniedHttpException('Draft continuation requires a non-default unpublished moderation state.');
          }
        }
      }
      $draft->setNewRevision(TRUE);
      $draft->isDefaultRevision(FALSE);
      $draft->setRevisionUserId($this->user->id());
      $draft->setRevisionCreationTime($this->time->getRequestTime());
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
      $draft->save();
      $stored_live = $storage->loadUnchanged($entity->id());
      if ((string) $stored_live->getRevisionId() !== $versions[1]
        || $draft->isPublished() || $draft->isDefaultRevision()) {
        throw new ConflictHttpException('Draft continuation changed the live revision; the save was rolled back.');
      }
      $primary_data = new ResourceObjectData([ResourceObject::createFromEntity($resource_type, $draft)], 1);
      return $this->buildWrappedResponse($primary_data, $request, $this->getIncludes($request, $primary_data));
    }
    catch (\Throwable $exception) {
      $transaction->rollBack();
      throw $exception;
    }
  }

}
