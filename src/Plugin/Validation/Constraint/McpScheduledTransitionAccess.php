<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Validation\Attribute\Constraint;
use Symfony\Component\Validator\Constraint as SymfonyConstraint;

/**
 * Wraps SCMI's transition-permission check on scheduled-state fields.
 *
 * Replaces SchedulerModerationTransitionAccess on publish_state and
 * unpublish_state (see mcp_sentinel_entity_base_field_info_alter()). Every
 * request the scheduled-publish gate does not take over runs SCMI's own
 * validator unchanged. A governed request whose profile allows scheduled
 * publishing skips the role-permission check; McpScheduledPublish applies the
 * profile instead.
 */
#[Constraint(
  id: 'McpScheduledTransitionAccess',
  label: new TranslatableMarkup('MCP Sentinel scheduled transition access', [], ['context' => 'Validation']),
  type: 'string',
)]
final class McpScheduledTransitionAccess extends SymfonyConstraint {
}
