<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Validation\Attribute\Constraint;
use Symfony\Component\Validator\Constraint as SymfonyConstraint;

/**
 * Denies a governed agent from publishing a moderated content entity.
 *
 * This is the moderated half of the deny-publish gate. It is attached to every
 * content entity type (see mcp_sentinel_entity_type_alter()) and enforced when
 * the entity is validated — the seam JSON:API and REST always run before a
 * write. Validation sees the entity carrying the *incoming* moderation_state,
 * so the gate can compare the transition target against the stored state and
 * deny only a go-live (a transition *into* a published state) while leaving the
 * non-publish editorial transitions the agent's role grants untouched.
 *
 * The gate previously lived in mcp_sentinel_entity_field_access() ('edit'), but
 * JSON:API checks field edit-access against the *stored* field value
 * (EntityResource::checkPatchFieldAccess() reads $destination->get($field)), so
 * the hook never saw the incoming target and wrongly blocked every
 * moderation_state write on an already-published node — including a legitimate
 * published → draft transition. Validation is the correct layer because it runs
 * on the parsed entity with the new values.
 *
 * The unmoderated status-flag path is handled separately by the presave
 * fallback in mcp_sentinel_entity_presave().
 */
#[Constraint(
  id: 'McpDenyPublish',
  label: new TranslatableMarkup('MCP Sentinel deny publish', [], ['context' => 'Validation'])
)]
final class McpDenyPublish extends SymfonyConstraint {

  /**
   * The violation message shown when a go-live is denied.
   *
   * Kept verbatim: the connector and the module's tests match on this exact
   * string.
   *
   * @var string
   */
  public string $message = 'Publishing is denied by MCP Sentinel.';

}
