<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Validation\Attribute\Constraint;
use Symfony\Component\Validator\Constraint as SymfonyConstraint;

/**
 * Denies a governed write that conflicts with a lock or a stale version.
 *
 * The validated-seam surface of the shared write-precondition boundary
 * (d.o #3616541): attached to every content entity type (see
 * mcp_sentinel_entity_type_alter()) so JSON:API, REST, and forms refuse a
 * conflicting governed save with a 422 before anything mutates. The actual
 * contract lives in McpWritePreconditions — an active lock held by a
 * different server-resolved principal, or a save from a copy that is no
 * longer the stored default revision. The unvalidated seam (custom code,
 * Drush) is covered by the presave/predelete aborts in mcp_sentinel.module.
 */
#[Constraint(
  id: 'McpWriteConflict',
  label: new TranslatableMarkup('MCP Sentinel write conflict', [], ['context' => 'Validation'])
)]
final class McpWriteConflict extends SymfonyConstraint {
}
