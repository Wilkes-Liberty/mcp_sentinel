<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;

/**
 * Decides what the publish gate governs, and whether a transition publishes.
 *
 * This is the single source of truth for the publish gate's two scope
 * questions: "is this entity's published status ours to govern?"
 * (::governsPublishedStatus) and "does this transition publish?"
 * (::targetIsPublishedState). Every consumer — the value-aware field-access
 * hook (mcp_sentinel_entity_field_access), the presave fallback
 * (mcp_sentinel_entity_presave), the McpDenyPublish constraint, and the
 * workflow-transition tool (McpWorkflowTransitionTool) — asks here, so the
 * JSON:API write path and the server-tool path agree on exactly which entities
 * and which transitions are in scope.
 *
 * The publish gate must remain conservative: only a *known, published* target
 * state counts as a publish. Anything else — Content Moderation not installed,
 * no workflow for the entity, or an unknown state machine name — returns FALSE,
 * so this method never blocks a non-publish editorial transition (draft,
 * submit_for_review, restore, archive) and never masks an invalid state (which
 * the ModerationState constraint reports instead).
 */
final class McpModerationGate {

  /**
   * Entity types whose published status the gate never governs, by name.
   *
   * Reserved for entity types that are structurally outside editorial
   * publication but cannot be recognised generically. Everything not listed
   * here, and not a composite child (see ::governsPublishedStatus), stays
   * governed — the gate fails closed, so an unfamiliar publishable entity type
   * is gated rather than silently exempt.
   */
  private const UNGOVERNED_ENTITY_TYPES = [
    // A path alias is routing metadata, not editorial content: its status means
    // "is this alias active", and the aliased path's own access still decides
    // what a visitor may see. Pathauto mints one as a side effect of saving a
    // node, so governing it would let a routine content write silently strip
    // the page's canonical URL.
    'path_alias',
  ];

  /**
   * Constructs the moderation gate.
   *
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed (injected with the optional-service '@?' syntax).
   */
  public function __construct(
    protected readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * Whether the publish gate governs this entity's published status.
   *
   * `deny_publish` is about editorial go-live: an agent must not make content
   * publicly visible without a human. Two kinds of publishable entity are
   * outside that meaning, and governing them turns a routine content write into
   * silent data loss:
   *
   * - **Composite children** (paragraphs, and anything else declaring
   *   `entity_revision_parent_type_field`). Such an entity is never published
   *   in its own right — it renders if and only if its host does, and its
   *   status is an implementation detail of the host's composition. It is also
   *   saved as a side effect of saving the host, so governing it means a
   *   governed write to an already-published page silently blanks that page's
   *   content while the write reports success.
   * - **Routing metadata** listed in self::UNGOVERNED_ENTITY_TYPES.
   *
   * Neither exemption weakens the gate: the host entity's own published status
   * is still governed, and an alias only routes to a path whose access is
   * decided elsewhere. Anything not matching an exemption stays governed, so
   * the default is closed.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being saved or validated.
   *
   * @return bool
   *   TRUE when the gate governs this entity's published status.
   */
  public function governsPublishedStatus(EntityInterface $entity): bool {
    if (in_array($entity->getEntityTypeId(), self::UNGOVERNED_ENTITY_TYPES, TRUE)) {
      return FALSE;
    }
    // A composite child's published status is an implementation detail of its
    // host's composition, not editorial go-live — so the publish gate does not
    // govern it here. Direct writes to a composite child pinned by a published
    // host are handled separately by McpCompositeRedirect, which keeps the pin
    // untouched and lands the edit as a host draft (see GitHub #46).
    return !$this->isCompositeChild($entity);
  }

  /**
   * Whether the entity is a composite child (e.g. a paragraph).
   *
   * A composite child declares the entity-type key holding its parent's entity
   * type (`entity_revision_parent_type_field`). Such an entity is never
   * published in its own right — it renders if and only if its host does — and
   * is saved as a side effect of saving the host.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity to test.
   *
   * @return bool
   *   TRUE when the entity type is a composite (revision-parented) child.
   */
  public function isCompositeChild(EntityInterface $entity): bool {
    return $entity->getEntityType()->get('entity_revision_parent_type_field') !== NULL;
  }

  /**
   * Whether a target moderation state publishes the given entity.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being transitioned.
   * @param string $state
   *   The target moderation state machine name.
   *
   * @return bool
   *   TRUE only when the target is a known published state in the entity's
   *   workflow; FALSE in every other case (no moderation, no workflow, empty or
   *   unknown state).
   */
  public function targetIsPublishedState(ContentEntityInterface $entity, string $state): bool {
    if ($this->moderationInformation === NULL || $state === '') {
      return FALSE;
    }
    $workflow = $this->moderationInformation->getWorkflowForEntity($entity);
    if ($workflow === NULL) {
      return FALSE;
    }
    $typePlugin = $workflow->getTypePlugin();
    if (!$typePlugin->hasState($state)) {
      // Unknown state — not a publish; the ModerationState constraint reports.
      return FALSE;
    }
    $target = $typePlugin->getState($state);
    return $target instanceof ContentModerationState && $target->isPublishedState();
  }

}
