<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Exception;

/**
 * Refuses a tool call before dispatch for an identity/tenant violation.
 */
final class McpPrincipalContextDeniedException extends \RuntimeException {

  /**
   * Reserved identity or tenant key in tool arguments.
   */
  public const RESERVED_IDENTITY_ARGUMENT = 'reserved_identity_argument';

  /**
   * Network call whose validated token has no tenant claim.
   */
  public const MISSING_TENANT_CLAIM = 'missing_tenant_claim';

  /**
   * The principal-context dispatcher is not wired.
   */
  public const MISSING_DISPATCHER = 'missing_dispatcher';

  /**
   * No verified principal (missing iss/sub/azp/act.sub).
   */
  public const MISSING_PRINCIPAL = 'missing_principal';

  /**
   * A second seal with a different principal was refused.
   */
  public const RESEAL_REFUSED = 'reseal_refused';

  /**
   * Spoofchecker is missing; look-alike reserved-key checks cannot run.
   */
  public const LOOKALIKE_CHECK_UNAVAILABLE = 'lookalike_check_unavailable';

  /**
   * Token issuer is not Paladin (DEV-843; no non-IdP path).
   */
  public const NON_IDP_ISSUER = 'non_idp_issuer';

  /**
   * Sealed token omits the exact OAuth scope the surface requires.
   */
  public const REQUIRED_SCOPE_MISSING = 'required_scope_missing';

  /**
   * Constructs a fail-closed refusal.
   *
   * @param string $reasonCode
   *   Stable machine reason.
   * @param string $message
   *   Operator- and agent-facing text. Must not contain secrets.
   */
  public function __construct(
    public readonly string $reasonCode,
    string $message,
  ) {
    parent::__construct($message);
  }

}
