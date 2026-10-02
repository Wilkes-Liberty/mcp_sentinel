<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\DependencyInjection\ClassResolverInterface;
use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Validation\ConstraintManager;
use Drupal\mcp_sentinel\Service\McpScheduledPublishGate;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\ConstraintValidatorInterface;

/**
 * Runs SCMI's transition-permission check unless Sentinel takes over.
 */
final class McpScheduledTransitionAccessValidator extends ConstraintValidator implements ContainerInjectionInterface {

  /**
   * Constructs the validator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpScheduledPublishGate $gate
   *   Decides whether Sentinel takes over the request.
   * @param \Drupal\Core\Validation\ConstraintManager $constraintManager
   *   Builds SCMI's original constraint.
   * @param \Drupal\Core\DependencyInjection\ClassResolverInterface $classResolver
   *   Instantiates SCMI's original validator.
   */
  public function __construct(
    private readonly McpScheduledPublishGate $gate,
    private readonly ConstraintManager $constraintManager,
    private readonly ClassResolverInterface $classResolver,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.scheduled_publish_gate'),
      $container->get('validation.constraint'),
      $container->get('class_resolver'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function validate(mixed $value, Constraint $constraint): void {
    if (!$value instanceof FieldItemListInterface) {
      return;
    }
    if ($this->gate->takesOver($value->getEntity()->getEntityTypeId())) {
      return;
    }
    if (!$this->constraintManager->hasDefinition(McpScheduledPublishGate::SCMI_TRANSITION_CONSTRAINT)) {
      return;
    }
    $original = $this->constraintManager->create(McpScheduledPublishGate::SCMI_TRANSITION_CONSTRAINT, []);
    $validator = $this->classResolver->getInstanceFromDefinition($original->validatedBy());
    if (!$validator instanceof ConstraintValidatorInterface) {
      return;
    }
    $validator->initialize($this->context);
    $validator->validate($value, $original);
  }

}
