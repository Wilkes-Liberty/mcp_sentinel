<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Service\McpScheduledPublishGate;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates scheduled states on a governed write against the profile.
 *
 * Early-returns for ungoverned requests, for sites without Scheduler Content
 * Moderation Integration, and for entities without its fields, so the
 * site-wide attachment is cheap.
 */
final class McpScheduledPublishValidator extends ConstraintValidator implements ContainerInjectionInterface {

  /**
   * Constructs the validator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves whether the request is governed and which profile applies.
   * @param \Drupal\mcp_sentinel\Service\McpScheduledPublishGate $gate
   *   Decides which scheduled changes the profile refuses.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpScheduledPublishGate $gate,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.policy_resolver'),
      $container->get('mcp_sentinel.scheduled_publish_gate'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function validate(mixed $value, Constraint $constraint): void {
    if (!$value instanceof ContentEntityInterface || !$this->gate->appliesTo($value)) {
      return;
    }
    if (!$this->policyResolver->isGoverned()) {
      return;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL) {
      return;
    }
    $changes = $this->gate->scheduledChanges($value, $this->gate->storedOriginal($value));
    foreach ($this->gate->refusals($value, $profile, $changes) as $message) {
      $this->context->buildViolation($message)->addViolation();
    }
  }

}
