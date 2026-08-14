<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionLogInterface;
use Drupal\Core\Session\AccountProxyInterface;

/**
 * Redirects governed in-place edits of published unmoderated content.
 *
 * An already-published entity without a moderation workflow used to be
 * editable in place over the governed agent channel: the agent's field values
 * replaced the live default revision, and the presave publish-gate backstop
 * then forced the entity unpublished — live content mutated AND taken down in
 * one save (d.o #3616542). The human-publication invariant requires that an
 * agent write never changes what the public sees:
 *
 * - **Redirect** (revisionable entity types): the save is converted into a new
 *   unpublished non-default (forward) revision. The live default revision is
 *   untouched and stays published; a human publishes the forward revision or
 *   discards it.
 * - **Deny** (non-revisionable entity types): there is nowhere safe to put the
 *   edit, so it is refused. Validated seams (JSON:API, REST, forms) report the
 *   refusal as a 422 via McpDenyPublishValidator; the unvalidated seam
 *   (custom code, Drush) aborts the save after writing an evidence row —
 *   a silent no-op would be indistinguishable from success.
 *
 * The unmoderated counterpart of McpCompositeRedirect (GitHub #46), sharing
 * its presave/post-save two-phase shape and its audit conventions.
 */
final class McpUnmoderatedForwardRevision {

  public const DECISION_IGNORE = 'ignore';
  public const DECISION_REDIRECT = 'redirect';
  public const DECISION_DENY = 'deny';

  /**
   * The stable refusal for entity types that cannot carry a forward revision.
   */
  public const IN_PLACE_DENY_MESSAGE = 'Publishing is denied by MCP Sentinel: this published content cannot be changed in place, and its entity type does not support forward revisions. A human must publish a revised version.';

  /**
   * Live revision ids stashed at presave, keyed by entity UUID.
   *
   * @var array<string, int|string>
   */
  private array $stash = [];

  /**
   * Constructs the redirect service.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves whether the request is governed and which profile applies.
   * @param \Drupal\mcp_sentinel\Service\McpModerationGate $moderationGate
   *   Decides whether the entity's published status is editorial go-live.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Loads the stored entity to read its pre-edit published status.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes the evidence rows.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The acting agent account, recorded on the forward revision.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Provides the forward revision's creation time.
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed. Moderated entities are governed by the moderated gate.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpModerationGate $moderationGate,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly McpAuditLogger $auditLogger,
    private readonly AccountProxyInterface $currentUser,
    private readonly TimeInterface $time,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * Classifies a save as ignore, redirect, or deny.
   *
   * Only a governed, publish-denied, unmoderated, gate-governed in-place edit
   * of stored-published content that stays published is in scope. A pure
   * takedown (incoming unpublished) and a go-live (stored unpublished) belong
   * to the existing gates.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being validated or saved.
   *
   * @return string
   *   One of the DECISION_* constants.
   */
  public function classify(EntityInterface $entity): string {
    if (!$entity instanceof ContentEntityInterface
      || !$entity instanceof EntityPublishedInterface
      || $entity->isNew()
      || !$entity->isPublished()
    ) {
      return self::DECISION_IGNORE;
    }
    if (!$this->policyResolver->isGoverned()) {
      return self::DECISION_IGNORE;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL || !$profile->deniesPublishForEntityType($entity->getEntityTypeId())) {
      return self::DECISION_IGNORE;
    }
    if (!$this->moderationGate->governsPublishedStatus($entity)) {
      return self::DECISION_IGNORE;
    }
    if ($this->moderationInformation !== NULL && $this->moderationInformation->isModeratedEntity($entity)) {
      return self::DECISION_IGNORE;
    }
    if (!$this->storedIsPublished($entity)) {
      return self::DECISION_IGNORE;
    }

    return $entity->getEntityType()->isRevisionable()
      ? self::DECISION_REDIRECT
      : self::DECISION_DENY;
  }

  /**
   * Phase A: convert an in-place edit into a forward revision, or refuse it.
   *
   * Called from hook_entity_presave, before the publish-gate backstop — the
   * redirect unpublishes the (new, non-default) revision, which also keeps the
   * backstop's status flip away from it.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being saved.
   */
  public function onPresave(EntityInterface $entity): void {
    $decision = $this->classify($entity);
    if ($decision === self::DECISION_IGNORE || !$entity instanceof ContentEntityInterface) {
      return;
    }

    if ($decision === self::DECISION_DENY) {
      // Validated seams were already refused with a 422 by the constraint; an
      // unvalidated seam reaching here must abort. Evidence first: the refusal
      // has to be observable even though the save never happens.
      $this->auditLogger->log('unmoderated_in_place_denied', [
        'entity_type' => $entity->getEntityTypeId(),
        'bundle' => $entity->bundle(),
        'id' => $entity->id(),
        'label' => $entity->label(),
        'note' => 'In-place edit of published non-revisionable content refused on an unvalidated seam; the save was aborted.',
      ]);
      throw new \RuntimeException(self::IN_PLACE_DENY_MESSAGE);
    }

    /** @var \Drupal\Core\Entity\ContentEntityInterface&\Drupal\Core\Entity\EntityPublishedInterface $entity */
    $this->stash[$entity->uuid()] = $entity->getLoadedRevisionId();
    $entity->setNewRevision(TRUE);
    $entity->isDefaultRevision(FALSE);
    $entity->setUnpublished();
    if ($entity instanceof RevisionLogInterface) {
      $entity->setRevisionLogMessage('Unpublished forward revision created by MCP Sentinel from a governed edit of published content (d.o #3616542); the live revision is unchanged.');
      $entity->setRevisionUserId($this->currentUser->id());
      $entity->setRevisionCreationTime($this->time->getRequestTime());
    }
  }

  /**
   * Phase B: record the evidence row naming both revisions.
   *
   * Called from hook_entity_update once the forward revision id exists.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The just-saved entity.
   */
  public function onPostSave(EntityInterface $entity): void {
    if (!$entity instanceof ContentEntityInterface) {
      return;
    }
    $uuid = $entity->uuid();
    if ($uuid === NULL || !isset($this->stash[$uuid])) {
      return;
    }
    $liveRevisionId = $this->stash[$uuid];
    unset($this->stash[$uuid]);

    $this->auditLogger->log('unmoderated_forward_revision', [
      'entity_type' => $entity->getEntityTypeId(),
      'bundle' => $entity->bundle(),
      'id' => $entity->id(),
      'label' => $entity->label(),
      'live_revision_id' => $liveRevisionId,
      'forward_revision_id' => $entity->getRevisionId(),
      'note' => 'Governed edit of published unmoderated content stored as an unpublished forward revision; the live revision is unchanged.',
    ]);
  }

  /**
   * Whether the entity's stored default revision is published.
   *
   * Reads from storage rather than $entity->original so classify() answers the
   * same way at validation time (original not yet populated) and at presave.
   * Fails closed by treating an unloadable stored entity as unpublished — the
   * go-live gates own that case.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being classified.
   *
   * @return bool
   *   TRUE only when the stored default revision is confirmed published.
   */
  private function storedIsPublished(ContentEntityInterface $entity): bool {
    $id = $entity->id();
    if ($id === NULL) {
      return FALSE;
    }
    $stored = $this->entityTypeManager
      ->getStorage($entity->getEntityTypeId())
      ->loadUnchanged($id);

    return $stored instanceof EntityPublishedInterface && $stored->isPublished();
  }

}
