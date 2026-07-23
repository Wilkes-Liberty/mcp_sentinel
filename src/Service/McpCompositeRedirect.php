<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Psr\Log\LoggerInterface;

/**
 * Governs direct writes to composite children pinned by published content.
 *
 * A direct JSON:API PATCH to a paragraph whose current revision is pinned by a
 * published host's default revision changes the live render in place — an
 * effective publish that bypasses the moderation gate (GitHub #46). This
 * service decides, and carries out, the response under a deny-publish profile:
 *
 * - **redirect**: the common, cleanly handled case (a single, un-nested,
 *   moderated, published host). The paragraph edit is saved as a *new* revision
 *   (leaving the pinned revision untouched, so the live page never changes) and
 *   a host **draft** forward revision is created that re-pins to the new
 *   paragraph revision. The edit lands as a reviewable draft.
 * - **deny**: cases that cannot be drafted safely (nested chains, multiple
 *   hosts, an unmoderated host, or no non-published state within the profile's
 *   ceiling). The write is refused with a 422 by the McpDenyPublish constraint,
 *   never mutated in place — "nothing goes live" holds in every case.
 *
 * The decision distinguishes a *direct* paragraph write from a host cascade
 * (saving a node re-saves its paragraphs) by the JSON:API route: only when the
 * request's resource type is this paragraph does the gate apply, so the
 * intentional host-cascade exemption in McpModerationGate is preserved.
 */
final class McpCompositeRedirect {

  public const DECISION_IGNORE = 'ignore';
  public const DECISION_REDIRECT = 'redirect';
  public const DECISION_DENY = 'deny';

  /**
   * Reentrancy guard: TRUE while a host draft is being saved.
   *
   * Creating the host draft cascades back into paragraph save hooks; the guard
   * makes those nested saves pass through untouched.
   */
  private bool $inRedirect = FALSE;

  /**
   * Per-request memo of decisions, keyed by entity uuid.
   *
   * @var array<string, array{decision: string, pins: list<array{host: \Drupal\Core\Entity\ContentEntityInterface, field: string, delta: int}>, draft_state: ?string, old_revision_id: int|string|null, reasons: list<string>}>
   */
  private array $decisions = [];

  /**
   * Stash of pending redirects awaiting completion, keyed by entity uuid.
   *
   * @var array<string, array{pins: list<array{host: \Drupal\Core\Entity\ContentEntityInterface, field: string, delta: int}>, draft_state: ?string, old_revision_id: int|string|null}>
   */
  private array $stash = [];

  /**
   * Constructs the redirect orchestrator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves governance and the active profile.
   * @param \Drupal\mcp_sentinel\Service\McpPinnedCompositeLocator $locator
   *   Finds the published host(s) pinning a composite child's revision.
   * @param \Drupal\mcp_sentinel\Service\McpModerationGate $moderationGate
   *   Identifies composite children.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Loads stored revisions and host entities.
   * @param \Drupal\Core\Routing\RouteMatchInterface $routeMatch
   *   Distinguishes a direct paragraph write from a host cascade.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Records the redirect (and denied-in-place) outcomes.
   * @param \Psr\Log\LoggerInterface $logger
   *   The mcp_sentinel channel logger.
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed (redirect then always resolves to deny).
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpPinnedCompositeLocator $locator,
    private readonly McpModerationGate $moderationGate,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly RouteMatchInterface $routeMatch,
    private readonly McpAuditLogger $auditLogger,
    private readonly LoggerInterface $logger,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * Classifies how a composite-child write must be handled.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being validated or saved.
   *
   * @return string
   *   One of self::DECISION_IGNORE, DECISION_REDIRECT, or DECISION_DENY.
   */
  public function classify(EntityInterface $entity): string {
    return $this->decide($entity)['decision'];
  }

  /**
   * Phase A: mark a redirectable paragraph write for a new revision.
   *
   * Called from hook_entity_presave. Preserving the pinned revision (via a new
   * revision on the edited paragraph) and stashing the pins for the post-save
   * completion. On a denied case reaching an *unvalidated* seam (Drush/custom
   * code, where the constraint never ran), still forces a new revision so the
   * pinned revision is never mutated, and audits the refusal.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being saved.
   */
  public function onPresave(EntityInterface $entity): void {
    if ($this->inRedirect || !$entity instanceof ContentEntityInterface) {
      return;
    }
    $decision = $this->decide($entity);
    if ($decision['decision'] === self::DECISION_REDIRECT) {
      $entity->setNewRevision(TRUE);
      $this->stash[$entity->uuid()] = [
        'pins' => $decision['pins'],
        'draft_state' => $decision['draft_state'],
        'old_revision_id' => $decision['old_revision_id'],
      ];
    }
    elseif ($decision['decision'] === self::DECISION_DENY) {
      // The constraint returns a 422 on validated paths (JSON:API/REST), so a
      // deny normally never reaches here. On an unvalidated seam, keep the
      // pinned revision safe and make the silent refusal observable.
      $entity->setNewRevision(TRUE);
      $this->auditLogger->log('composite_redirect_denied', [
        'entity_type' => $entity->getEntityTypeId(),
        'bundle' => $entity->bundle(),
        'id' => $entity->id() ?: '(new)',
        'label' => $entity->label(),
        'reasons' => $decision['reasons'],
        'note' => 'In-place edit of a paragraph pinned by published content was refused (unvalidated seam); saved as a detached revision.',
      ]);
      $this->logger->warning(
        'MCP Sentinel refused an in-place edit of @type "@label" pinned by published content on an unvalidated save (@reasons); the edit was saved as a detached revision, not published.',
        [
          '@type' => $entity->getEntityTypeId(),
          '@label' => (string) $entity->label(),
          '@reasons' => implode(',', $decision['reasons']),
        ]
      );
    }
  }

  /**
   * Phase B: complete a redirect by drafting the host(s).
   *
   * Called from hook_entity_insert and hook_entity_update. The new paragraph
   * revision id is now known; for each stashed pin a host draft forward
   * revision is created re-pinning to it, leaving the published default
   * revision untouched.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The just-saved paragraph.
   */
  public function onPostSave(EntityInterface $entity): void {
    if ($this->inRedirect || !$entity instanceof ContentEntityInterface) {
      return;
    }
    $uuid = $entity->uuid();
    if (!isset($this->stash[$uuid])) {
      return;
    }
    $data = $this->stash[$uuid];
    unset($this->stash[$uuid]);

    $newRevisionId = $entity->getRevisionId();
    $this->inRedirect = TRUE;
    try {
      foreach ($data['pins'] as $pin) {
        $this->draftHost($entity, $newRevisionId, $pin, $data['draft_state']);
      }
    }
    finally {
      $this->inRedirect = FALSE;
    }
  }

  /**
   * Creates a host draft forward revision re-pinning to the new child revision.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $child
   *   The edited paragraph (now at its new revision).
   * @param int|string $newRevisionId
   *   The paragraph's new revision id carrying the edit.
   * @param array{host: \Drupal\Core\Entity\ContentEntityInterface, field: string, delta: int} $pin
   *   The published-host pin descriptor.
   * @param string|null $draftState
   *   The moderation state id to set on the host draft.
   */
  private function draftHost(ContentEntityInterface $child, int|string $newRevisionId, array $pin, ?string $draftState): void {
    $hostType = $pin['host']->getEntityTypeId();
    $storage = $this->entityTypeManager->getStorage($hostType);
    $host = $storage->loadUnchanged($pin['host']->id());
    if (!$host instanceof ContentEntityInterface || !$host->hasField($pin['field'])) {
      return;
    }

    $host->setNewRevision(TRUE);
    $host->isDefaultRevision(FALSE);
    if ($draftState !== NULL && $host->hasField('moderation_state')) {
      $host->set('moderation_state', $draftState);
    }
    if ($host->getEntityType()->isRevisionable() && $host->hasField('revision_log_message')) {
      $host->set('revision_log_message', 'Draft created by MCP Sentinel from a governed paragraph edit (GitHub #46).');
    }

    // Re-pin the ERR item to the edited paragraph's new revision. Attaching the
    // already-saved revision keeps the host draft pointing at the edit.
    $childStorage = $this->entityTypeManager->getStorage($child->getEntityTypeId());
    $childRevision = $childStorage instanceof RevisionableStorageInterface
      ? $childStorage->loadRevision($newRevisionId)
      : NULL;
    $item = $host->get($pin['field'])->get($pin['delta']);
    if ($item !== NULL) {
      $item->set('target_id', $child->id());
      $item->set('target_revision_id', $newRevisionId);
      if ($childRevision instanceof ContentEntityInterface) {
        $item->set('entity', $childRevision);
      }
    }

    $host->save();

    $this->auditLogger->log('composite_redirect', [
      'entity_type' => $child->getEntityTypeId(),
      'bundle' => $child->bundle(),
      'id' => $child->id(),
      'label' => $child->label(),
      'host_type' => $hostType,
      'host_id' => $host->id(),
      'host_field' => $pin['field'],
      'host_delta' => $pin['delta'],
      'new_revision_id' => $newRevisionId,
      'host_draft_revision_id' => $host->getRevisionId(),
      'draft_state' => $draftState,
      'note' => 'Governed paragraph edit landed as a host draft; the published revision was left untouched.',
    ]);
  }

  /**
   * Computes and memoises the decision for an entity.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to classify.
   *
   * @return array{decision: string, pins: list<array{host: \Drupal\Core\Entity\ContentEntityInterface, field: string, delta: int}>, draft_state: ?string, old_revision_id: int|string|null, reasons: list<string>}
   *   The decision record.
   */
  private function decide(EntityInterface $entity): array {
    $ignore = [
      'decision' => self::DECISION_IGNORE,
      'pins' => [],
      'draft_state' => NULL,
      'old_revision_id' => NULL,
      'reasons' => [],
    ];

    if (!$entity instanceof ContentEntityInterface) {
      return $ignore;
    }
    // Only composite children are in scope.
    if (!$this->moderationGate->isCompositeChild($entity)) {
      return $ignore;
    }
    // Governance + deny-publish for this type.
    if (!$this->policyResolver->isGoverned()) {
      return $ignore;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL || !$profile->deniesPublishForEntityType($entity->getEntityTypeId())) {
      return $ignore;
    }
    // Only a *direct* write to this paragraph resource — never a host cascade.
    if (!$this->isDirectWriteTarget($entity)) {
      return $ignore;
    }
    // Create is out of scope (an unreferenced paragraph is inert); only an
    // existing paragraph can be pinned by a published host.
    $id = $entity->id();
    if ($id === NULL) {
      return $ignore;
    }

    $uuid = $entity->uuid();
    if (isset($this->decisions[$uuid])) {
      return $this->decisions[$uuid];
    }

    $storage = $this->entityTypeManager->getStorage($entity->getEntityTypeId());
    $stored = $storage->loadUnchanged($id);
    if (!$stored instanceof ContentEntityInterface) {
      return $this->decisions[$uuid] = $ignore;
    }
    $oldRevisionId = $stored->getRevisionId();

    $analysis = $this->locator->analyze($stored, $oldRevisionId);
    if (!$analysis['pinned_by_published']) {
      // Not pinned by any published default revision — an in-place edit is not
      // a publish; leave it to the normal write gate.
      return $this->decisions[$uuid] = $ignore;
    }

    if (!$analysis['redirectable']) {
      return $this->decisions[$uuid] = [
        'decision' => self::DECISION_DENY,
        'pins' => [],
        'draft_state' => NULL,
        'old_revision_id' => $oldRevisionId,
        'reasons' => $analysis['reasons'],
      ];
    }

    // Topology is redirectable; confirm a safe draft state exists on the host.
    $host = $analysis['pins'][0]['host'];
    $draftState = $this->computeDraftState($host, $profile);
    if ($draftState === FALSE) {
      return $this->decisions[$uuid] = [
        'decision' => self::DECISION_DENY,
        'pins' => [],
        'draft_state' => NULL,
        'old_revision_id' => $oldRevisionId,
        'reasons' => ['no_safe_draft_state'],
      ];
    }

    return $this->decisions[$uuid] = [
      'decision' => self::DECISION_REDIRECT,
      'pins' => $analysis['pins'],
      'draft_state' => $draftState,
      'old_revision_id' => $oldRevisionId,
      'reasons' => [],
    ];
  }

  /**
   * Whether the current request targets this paragraph resource directly.
   *
   * Compares the JSON:API route's resource type (set as the 'resource_type'
   * route default, of the form "<entity_type>--<bundle>") to this entity. A
   * direct paragraph PATCH matches; a host node PATCH that cascades to its
   * paragraphs does not, so the intentional host-cascade exemption stands.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The paragraph being saved.
   *
   * @return bool
   *   TRUE when the routed resource is this paragraph's type and bundle.
   */
  private function isDirectWriteTarget(ContentEntityInterface $entity): bool {
    $route = $this->routeMatch->getRouteObject();
    if ($route === NULL) {
      return FALSE;
    }
    // 'resource_type' is JSON:API's route default (Routes::RESOURCE_TYPE_KEY);
    // referenced by literal to avoid a hard dependency on the jsonapi class.
    $resourceType = $route->getDefault('resource_type');
    if (!is_string($resourceType) || $resourceType === '') {
      return FALSE;
    }
    return $resourceType === $entity->getEntityTypeId() . '--' . $entity->bundle();
  }

  /**
   * Selects a non-published draft state for the host, within the ceiling.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $host
   *   The published host to draft.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The active policy profile (for max_moderation_state).
   *
   * @return string|false
   *   The chosen moderation state id, or FALSE when the host is not a moderated
   *   entity or no non-published state fits within the ceiling (→ deny).
   */
  private function computeDraftState(ContentEntityInterface $host, McpPolicyProfileInterface $profile): string|false {
    if ($this->moderationInformation === NULL
      || !$this->moderationInformation->isModeratedEntity($host)) {
      return FALSE;
    }
    $workflow = $this->moderationInformation->getWorkflowForEntity($host);
    if ($workflow === NULL) {
      return FALSE;
    }
    $typePlugin = $workflow->getTypePlugin();

    $max = $profile->getMaxModerationState();
    $ceilingWeight = ($max !== '' && $typePlugin->hasState($max))
      ? $typePlugin->getState($max)->weight()
      : NULL;

    // Prefer the workflow's default state when it is non-published and fits.
    $config = $typePlugin->getConfiguration();
    $default = $config['default_moderation_state'] ?? NULL;
    if (is_string($default) && $default !== '' && $typePlugin->hasState($default)) {
      $state = $typePlugin->getState($default);
      if ($state instanceof ContentModerationState
        && !$state->isPublishedState()
        && ($ceilingWeight === NULL || $state->weight() <= $ceilingWeight)) {
        return $default;
      }
    }

    // Otherwise the lowest-weight non-published state within the ceiling.
    $best = NULL;
    $bestId = FALSE;
    foreach ($typePlugin->getStates() as $stateId => $state) {
      if (!$state instanceof ContentModerationState || $state->isPublishedState()) {
        continue;
      }
      if ($ceilingWeight !== NULL && $state->weight() > $ceilingWeight) {
        continue;
      }
      if ($best === NULL || $state->weight() < $best->weight()) {
        $best = $state;
        $bestId = $stateId;
      }
    }
    return $bestId;
  }

}
