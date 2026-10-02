<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Validation\Attribute\Constraint;
use Symfony\Component\Validator\Constraint as SymfonyConstraint;

/**
 * Applies the policy profile to a governed scheduled state (d.o #3627557).
 *
 * Attached to every content entity type (see mcp_sentinel_entity_type_alter())
 * and reported at the entity level. JSON:API drops field-level violations for
 * fields absent from a PATCH payload, and a write that changes only publish_on
 * still changes the schedule, so the refusal must not hang off one field.
 *
 * @see \Drupal\mcp_sentinel\Service\McpScheduledPublishGate
 */
#[Constraint(
  id: 'McpScheduledPublish',
  label: new TranslatableMarkup('MCP Sentinel scheduled publish', [], ['context' => 'Validation'])
)]
final class McpScheduledPublish extends SymfonyConstraint {
}
