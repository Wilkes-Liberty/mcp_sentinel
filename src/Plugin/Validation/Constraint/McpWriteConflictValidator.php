<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\DependencyInjection\ContainerInjectionInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\mcp_sentinel\Service\McpWritePreconditions;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;

/**
 * Validates the shared write-precondition boundary on the validated seams.
 *
 * Delegates entirely to McpWritePreconditions so the constraint, the presave
 * abort, and the Tool-plugin checks all answer from one contract. Violations
 * are reported at the ENTITY level deliberately: a conflicting payload need
 * not contain any particular field, and JSON:API's filterByFields() drops
 * field-level violations for fields absent from the payload (the same lesson
 * McpDenyPublishValidator carries).
 */
final class McpWriteConflictValidator extends ConstraintValidator implements ContainerInjectionInterface {

  public function __construct(
    private readonly McpWritePreconditions $writePreconditions,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel.write_preconditions'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function validate(mixed $value, Constraint $constraint): void {
    if (!$value instanceof ContentEntityInterface || !$constraint instanceof McpWriteConflict) {
      return;
    }
    $conflict = $this->writePreconditions->evaluateWrite($value);
    if ($conflict !== NULL) {
      $this->context->buildViolation($this->writePreconditions->messageFor($conflict))
        ->addViolation();
    }
  }

}
