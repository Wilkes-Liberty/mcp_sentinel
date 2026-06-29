<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;

/**
 * Decides whether a target moderation state is a *published* state.
 *
 * This is the single source of truth for the publish gate's core question:
 * "does this transition publish?" Both the value-aware field-access hook
 * (mcp_sentinel_entity_field_access) and the workflow-transition tool
 * (McpWorkflowTransitionTool) use it, so the JSON:API write path and the
 * server-tool path agree on exactly which transitions are go-live.
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
