<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityPublishedInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\Service\McpModerationGate;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates the deny-publish gate for governed agents.
 *
 * Fires a violation only on a *go-live*, and applies the same rule to both
 * kinds of publishable entity:
 *
 * - **Moderated**: the incoming moderation_state is a published state, and the
 *   entity is either new or its stored state was not already published.
 * - **Unmoderated**: the incoming status is published, and the entity is either
 *   new or its stored status was not already published.
 *
 * That preserves the human-publish invariant — a deny-publish agent can never
 * transition content *into* a published state — while allowing published →
 * draft, draft → draft, published → archived, and in-place edits of
 * already-published content.
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
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpModerationGate $moderationGate,
    private readonly EntityTypeManagerInterface $entityTypeManager,
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
    // children and routing metadata — are never gated. See
    // McpModerationGate::governsPublishedStatus().
    if (!$this->moderationGate->governsPublishedStatus($value)) {
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

    // The target is a published state. This is a go-live (and therefore denied)
    // unless the entity is already published and merely being edited in place:
    // an existing entity whose stored state is also a published state is not
    // transitioning into publication. When the stored state cannot be confirmed
    // as published, fail closed and deny.
    if (!$value->isNew() && $this->originalIsPublishedState($value)) {
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
