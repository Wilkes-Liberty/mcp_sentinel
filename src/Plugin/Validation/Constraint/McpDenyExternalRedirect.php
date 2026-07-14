<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\Validation\Constraint;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\Core\Validation\Attribute\Constraint;
use Symfony\Component\Validator\Constraint as SymfonyConstraint;

/**
 * Denies a governed agent from pointing a redirect at an off-domain target.
 *
 * This is the open-redirect / phishing gate. It is attached to the redirect
 * entity type (see mcp_sentinel_entity_type_alter(), guarded so sites without
 * the redirect module are unaffected) and enforced when the entity is
 * validated — the seam JSON:API and REST always run before a write, and where
 * the incoming destination URI is visible.
 *
 * An unrestricted redirect is a classic open-redirect vector: a governed agent
 * could create /login → https://evil.example/login and turn the site's own
 * domain into a phishing springboard. Validation is the correct layer, and the
 * only one that sees the incoming value, for the same reason the McpDenyPublish
 * gate lives there: field edit-access checks run against the *stored* value, so
 * they never see the incoming target on a JSON:API/REST write.
 *
 * The validator early-returns for every non-governed request and every profile
 * that permits external redirects, so the attachment is cheap. Internal,
 * entity:, base:, and relative targets are always allowed — only a fully
 * external URL whose host is outside the allowlist is denied.
 */
#[Constraint(
  id: 'McpDenyExternalRedirect',
  label: new TranslatableMarkup('MCP Sentinel deny external redirect', [], ['context' => 'Validation'])
)]
final class McpDenyExternalRedirect extends SymfonyConstraint {

  /**
   * The violation message shown when an off-domain redirect target is denied.
   *
   * Kept verbatim: the module's tests match on this exact string.
   *
   * @var string
   */
  public string $message = 'Redirecting to an external domain is denied by MCP Sentinel.';

}
