<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\content_moderation\ContentModerationState;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\mcp_sentinel\Service\McpModerationGate;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates the moderated deny-publish gate for governed agents.
 *
 * Fires a violation only on a *go-live*: the incoming moderation_state is a
 * published state and the entity is either new or its stored state was not
 * already a published state. That preserves the human-publish invariant — a
 * deny-publish agent can never transition content *into* a published state —
 * while allowing published → draft, draft → draft, published → archived, and
 * in-place edits of already-published content.
 *
 * The validator early-returns for every non-governed, non-deny-publish, or
 * non-moderated entity, so the site-wide constraint attachment is cheap.
 */
final class McpDenyPublishValidator extends ConstraintValidator implements ContainerInjectionInterface {

  /**
   * Constructs the validator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves whether the request is governed and which profile applies.
   * @param \Drupal\mcp_sentinel\Service\McpModerationGate $moderationGate
   *   Decides whether a target moderation state is a published state.
   * @param \Drupal\content_moderation\ModerationInformationInterface|null $moderationInformation
   *   The moderation information service, or NULL when Content Moderation is
   *   not installed.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpModerationGate $moderationGate,
    private readonly ?ModerationInformationInterface $moderationInformation = NULL,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.policy_resolver'),
      $container->get('mcp_sentinel.moderation_gate'),
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
    if ($profile === NULL || !$profile->deniesPublish()) {
      return;
    }

    // Only the moderated path is gated here. Unmoderated publishable entities
    // are forced unpublished by the presave fallback in
    // mcp_sentinel_entity_presave().
    if ($this->moderationInformation === NULL
      || !$this->moderationInformation->isModeratedEntity($value)) {
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
