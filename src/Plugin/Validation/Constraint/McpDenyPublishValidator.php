<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\Service\McpCompositeRedirect;
use Drupal\mcp_sentinel\Service\McpModerationGate;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates the deny-publish gate for governed agents.
 *
 * Fires a violation on any save that would make agent-authored content live:
 *
 * - **Moderated**: the incoming moderation_state is a published state. That
 *   covers the transition into publication AND the published → published save
 *   (#3613146): a save that keeps a published state replaces the live default
 *   revision with new content — an effective re-publish with no human in the
 *   loop, previously allowed as an "in-place edit". The remedy rides the
 *   violation message: submit the edit with a non-published moderation_state
 *   (e.g. draft) to create a forward revision for human review.
 * - **Unmoderated**: the incoming status is published, and the entity is
 *   either new or its stored status was not already published. In-place edits
 *   remain allowed here — an unmoderated type has no forward-revision
 *   workflow to redirect the edit into, so gating it would leave agents no
 *   path at all; sites wanting that strictness deny writes for the type.
 *
 * Published → draft, draft → draft, and published → archived always pass.
 *
 * Reporting the unmoderated case here is what makes the refusal *visible*.
 * The presave backstop can only force status back to 0, which returns HTTP 200
 * with the entity silently altered: the caller cannot tell a refusal from a
 * success, and neither can anything built on top of it. A violation surfaces as
 * a 422 through JSON:API and REST, matching the moderated path.
 *
 * The validator early-returns for every non-governed entity, every profile that
 * permits publishing, and every entity the gate does not govern, so the
 * site-wide constraint attachment is cheap.
 */
final class McpDenyPublishValidator extends ConstraintValidator implements ContainerInjectionInterface {

  /**
   * Constructs the validator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves whether the request is governed and which profile applies.
   * @param \Drupal\mcp_sentinel\Service\McpModerationGate $moderationGate
   *   Decides what the gate governs and whether a transition publishes.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Loads the stored entity to read its pre-edit published status.
   * @param \Drupal\mcp_sentinel\Service\McpCompositeRedirect $compositeRedirect
   *   Decides whether a composite-child write must be denied (pinned by
   *   published content and not safely draftable) — see GitHub #46.
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpModerationGate $moderationGate,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly McpCompositeRedirect $compositeRedirect,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.policy_resolver'),
      $container->get('mcp_sentinel.moderation_gate'),
      $container->get('entity_type.manager'),
      $container->get('mcp_sentinel.composite_redirect'),
      $container->has('content_moderation.moderation_information')
        ? $container->get('content_moderation.moderation_information')
        : NULL,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function validate(mixed $value, Constraint $constraint): void {
    if (!$value instanceof ContentEntityInterface || !$constraint instanceof McpDenyPublish) {
      return;
    }

    // Governance scoping — identical to the module's other gates. Ungoverned
    // (cookie-session) traffic and profiles that permit publishing are never
    // gated here.
    if (!$this->policyResolver->isGoverned()) {
      return;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL
      || !$profile->deniesPublishForEntityType($value->getEntityTypeId())
    ) {
      return;
    }

    // Entities whose published status is not editorial go-live — composite
    // children and routing metadata — are not gated by the moderation-state
    // rules below. But a *direct* in-place edit of a composite child (a
    // paragraph)
    // pinned by a published host is itself an effective publish (GitHub #46).
    // The redirect orchestrator classifies it: a redirectable edit is allowed
    // here (the save hooks land it as a host draft), while one that cannot be
    // drafted safely is denied with a 422 — never mutated in place.
    if (!$this->moderationGate->governsPublishedStatus($value)) {
      if ($this->compositeRedirect->classify($value) === McpCompositeRedirect::DECISION_DENY) {
        $this->context->buildViolation('Publishing is denied by MCP Sentinel: this content is pinned by published content and cannot be changed in place. A human must publish a revised version.')
          ->addViolation();
      }
      return;
    }

    $moderated = $this->moderationInformation !== NULL
      && $this->moderationInformation->isModeratedEntity($value);

    if (!$moderated) {
      $this->validateUnmoderated($value, $constraint);
      return;
    }

    // The transition target is the entity's incoming moderation_state value.
    $target = $value->get('moderation_state')->value;
    if (!is_string($target) || $target === '') {
      return;
    }
    if (!$this->moderationGate->targetIsPublishedState($value, $target)) {
      // Draft, review, restore, archived … — never a go-live; allow.
      return;
    }

    // The target is a published state. Under deny-publish that is always
    // publish-class (#3613146). A new or unpublished entity is transitioning
    // into publication; an already-published one would have its live default
    // revision replaced with new content — observed in production as bulk
    // in-place mutations of published nodes, with no forward revision and
    // nothing for a human to approve. The previously-allowed "in-place edit"
    // case gets an actionable message naming the sanctioned path.
    if (!$value->isNew() && $this->originalIsPublishedState($value)) {
      $this->context->buildViolation('Publishing is denied by MCP Sentinel: this save would replace the live revision of published content. Submit the edit with a non-published moderation_state (for example "draft") to create a forward revision for human review.')
        ->atPath('moderation_state')
        ->addViolation();
      return;
    }

    $this->context->buildViolation($constraint->message)
      ->atPath('moderation_state')
      ->addViolation();
  }

  /**
   * Reports a denied go-live on an entity that is not under Content Moderation.
   *
   * The unmoderated equivalent of the moderated go-live rule: the published
   * flag itself is the transition. An entity that is not published is not going
   * live, and an entity whose stored status is already published is being
   * edited in place, not published.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being validated.
   * @param \Symfony\Component\Validator\Constraint $constraint
   *   The McpDenyPublish constraint carrying the message.
   */
  private function validateUnmoderated(ContentEntityInterface $entity, Constraint $constraint): void {
    if (!$entity instanceof EntityPublishedInterface || !$entity->isPublished()) {
      return;
    }
    if (!$entity->isNew() && $this->originalIsPublished($entity)) {
      return;
    }

    $this->context->buildViolation($constraint->message)
      ->atPath('status')
      ->addViolation();
  }

  /**
   * Whether the entity's stored (pre-edit) status is published.
   *
   * Reads the saved entity from storage rather than $entity->original, which is
   * not yet populated when JSON:API and REST validate before saving — the same
   * reason ::originalIsPublishedState() goes through the moderation information
   * service. Fails closed: when the stored entity cannot be loaded, the write
   * is treated as a go-live and denied.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being validated.
   *
   * @return bool
   *   TRUE only when the stored entity is confirmed published.
   */
  private function originalIsPublished(ContentEntityInterface $entity): bool {
    $id = $entity->id();
    if ($id === NULL) {
      return FALSE;
    }
    $stored = $this->entityTypeManager
      ->getStorage($entity->getEntityTypeId())
      ->loadUnchanged($id);

    return $stored instanceof EntityPublishedInterface && $stored->isPublished();
  }

  /**
   * Whether the entity's stored (pre-edit) moderation state is published.
   *
   * Reads the stored state from the loaded revision via the moderation
   * information service — the same mechanism core's own moderation-state
   * constraint uses — rather than $entity->original, which is not yet populated
   * when JSON:API and REST validate the entity before saving it.
   *
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The entity being validated.
   *
   * @return bool
   *   TRUE only when the stored state is a known published state.
   */
  private function originalIsPublishedState(ContentEntityInterface $entity): bool {
    if ($this->moderationInformation === NULL) {
      return FALSE;
    }
    $original = $this->moderationInformation->getOriginalState($entity);
    return $original instanceof ContentModerationState && $original->isPublishedState();
  }

}
