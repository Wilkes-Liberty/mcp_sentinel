<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Hook;

use Drupal\Core\Extension\ProceduralCall;
use Drupal\Core\Hook\Attribute\RemoveHook;

/**
 * Removes SCMI's entity access hook on Drupal 11.2 and later (d.o #3627557).
 *
 * The scheduled-publish gate calls
 * scheduler_content_moderation_integration_entity_access() from
 * mcp_sentinel_entity_access() for every request Sentinel does not take over.
 * The original must not also run on its own, or its forbidden result would
 * still lock a governed agent out of content it was allowed to schedule.
 *
 * Drupal 10.6 does not read this attribute; there,
 * mcp_sentinel_module_implements_alter() removes the hook. Removing an
 * implementation that does not exist (SCMI not installed) is a no-op.
 */
#[RemoveHook(
  'entity_access',
  class: ProceduralCall::class,
  method: 'scheduler_content_moderation_integration_entity_access',
)]
final class McpScheduledPublishHooks {
}
