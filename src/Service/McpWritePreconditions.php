<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableInterface;

/**
 * The shared write-precondition boundary for every governed mutation.
 *
 * Content locks and version preconditions used to be checked only inside the
 * governed Tool plugins: JSON:API, GraphQL, and direct governed saves could
 * bypass an active lock or silently overwrite a concurrent change
 * (d.o #3616541). This service is the one contract every channel runs:
 *
 * - **Lock conflict** — an active lock held by a different server-resolved
 *   principal denies the write (and the delete). The acting principal's own
 *   lock never blocks it: ownership is bound to the authenticated actor,
 *   never to anything a caller sends.
 * - **Stale version** — a save whose loaded copy claims to be the default
 *   revision, when the stored default has moved on, would overwrite the
 *   concurrent change; it is denied. Continuing a forward (non-default) draft
 *   is not a default-revision overwrite and passes.
 *
 * Validated seams (JSON:API, REST, forms) surface the denial as a 422 via the
 * McpWriteConflict constraint; the unvalidated seam (custom code, Drush)
 * aborts in presave/predelete after writing an evidence row. Passing governed
 * updates stash a receipt here that the post-save audit row completes with the
 * final target revision.
 *
 * Ungoverned (cookie-session) traffic is never gated: locks protect humans
 * from agents, not the other way around.
 */
final class McpWritePreconditions {

  public const CONFLICT_LOCK = 'content_lock_conflict';
  public const CONFLICT_STALE = 'stale_version_conflict';

  /**
   * The stable lock-conflict refusal.
   */
  public const LOCK_CONFLICT_MESSAGE = 'Write denied by MCP Sentinel: this content is locked by another actor. Retry after the lock is released or expires.';

  /**
   * The stable stale-version refusal.
   */
  public const STALE_VERSION_MESSAGE = 'Write denied by MCP Sentinel: the content changed after this copy was loaded. Reload the latest version and reapply the change.';

  /**
   * Receipts stashed at presave, keyed by entity UUID.
   *
   * @var array<string, array{lock: string, loaded_revision_id: int|string|null}>
   */
  private array $receipts = [];

  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpContentLock $contentLock,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Evaluates the write preconditions for a governed save.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being validated or saved.
   *
   * @return string|null
   *   NULL when the write may proceed, or one of the CONFLICT_* codes.
   */
  public function evaluateWrite(ContentEntityInterface $entity): ?string {
    if ($entity->isNew() || !$this->policyResolver->isGoverned()) {
      return NULL;
    }
    if ($this->contentLock->conflictsForActor($entity->getEntityTypeId(), (string) $entity->id())) {
      return self::CONFLICT_LOCK;
    }
    // Stale default: the loaded copy claims to be the default revision, but
    // the stored default has moved on — saving would overwrite the concurrent
    // change. A loaded forward (non-default) revision is a draft continuation
    // and is not gated here.
    if ($entity->getEntityType()->isRevisionable() && $entity->isDefaultRevision()) {
      $storedRevisionId = $this->storedDefaultRevisionId($entity);
      if ($storedRevisionId !== NULL
        && (int) $entity->getLoadedRevisionId() !== $storedRevisionId
      ) {
        return self::CONFLICT_STALE;
      }
    }
    return NULL;
  }

  /**
   * Evaluates the delete precondition for a governed delete.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being deleted.
   *
   * @return string|null
   *   NULL when the delete may proceed, or CONFLICT_LOCK.
   */
  public function evaluateDelete(ContentEntityInterface $entity): ?string {
    if ($entity->isNew() || !$this->policyResolver->isGoverned()) {
      return NULL;
    }
    return $this->contentLock->conflictsForActor($entity->getEntityTypeId(), (string) $entity->id())
      ? self::CONFLICT_LOCK
      : NULL;
  }

  /**
   * Returns the stable refusal message for a conflict code.
   *
   * @param string $conflict
   *   One of the CONFLICT_* codes.
   *
   * @return string
   *   The refusal message.
   */
  public function messageFor(string $conflict): string {
    return $conflict === self::CONFLICT_STALE
      ? self::STALE_VERSION_MESSAGE
      : self::LOCK_CONFLICT_MESSAGE;
  }

  /**
   * Stashes the checked precondition for a passing governed update.
   *
   * Called at presave, where the loaded revision id still names the copy the
   * precondition was checked against. The post-save audit row completes the
   * receipt with the final target revision via takeReceipt().
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being saved.
   */
  public function stashReceipt(ContentEntityInterface $entity): void {
    if ($entity->isNew() || !$this->policyResolver->isGoverned()) {
      return;
    }
    $uuid = $entity->uuid();
    if ($uuid === NULL) {
      return;
    }
    $this->receipts[$uuid] = [
      'lock' => $this->contentLock->heldByActor($entity->getEntityTypeId(), (string) $entity->id())
        ? 'held_by_actor'
        : 'none',
      'loaded_revision_id' => $entity->getLoadedRevisionId(),
    ];
  }

  /**
   * Returns and clears the stashed receipt, completed with the target version.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The just-saved entity.
   *
   * @return array|null
   *   The receipt (lock, loaded_revision_id, target_revision_id), or NULL when
   *   no precondition was stashed for this save.
   */
  public function takeReceipt(ContentEntityInterface $entity): ?array {
    $uuid = $entity->uuid();
    if ($uuid === NULL || !isset($this->receipts[$uuid])) {
      return NULL;
    }
    $receipt = $this->receipts[$uuid];
    unset($this->receipts[$uuid]);
    $receipt['target_revision_id'] = $entity->getRevisionId();
    return $receipt;
  }

  /**
   * The entity's stored default revision id, read uncached.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being evaluated.
   *
   * @return int|null
   *   The stored default revision id, or NULL when it cannot be determined.
   */
  private function storedDefaultRevisionId(ContentEntityInterface $entity): ?int {
    $id = $entity->id();
    if ($id === NULL) {
      return NULL;
    }
    $stored = $this->entityTypeManager
      ->getStorage($entity->getEntityTypeId())
      ->loadUnchanged($id);
    if (!$stored instanceof RevisionableInterface) {
      return NULL;
    }
    $revisionId = $stored->getRevisionId();
    return $revisionId === NULL ? NULL : (int) $revisionId;
  }

}
