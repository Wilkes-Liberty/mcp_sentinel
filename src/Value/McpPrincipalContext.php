<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Immutable principal + tenant context from a validated token.
 *
 * Built at the request boundary (DEV-844 / DEV-839). Tools receive this
 * as a separate parameter and must never read identity or tenant from
 * tool arguments.
 *
 * Grant tables (mcp_admin_grant and related) are superseded as an
 * identity source by this token-derived context. Retirement of those
 * tables is a later DEV-844 slice.
 */
final readonly class McpPrincipalContext {

  /**
   * Request attribute holding this frozen context.
   */
  public const REQUEST_ATTRIBUTE = 'mcp_sentinel.principal_context';

  /**
   * Request attribute holding validated Paladin/token claims.
   *
   * The auth layer (or a test) stamps the introspected token here. The
   * factory reads only this server-validated set — never tool arguments.
   */
  public const CLAIMS_ATTRIBUTE = 'mcp_sentinel.token_claims';

  /**
   * Request attribute that marks the call as a network surface.
   *
   * When TRUE, a missing tenant claim fails closed. CLI / stdio local
   * operator is not a network call.
   */
  public const NETWORK_ATTRIBUTE = 'mcp_sentinel.network_call';

  /**
   * Identity and tenant keys that must never appear in tool arguments.
   *
   * Checked case-insensitively on the top-level argument map before
   * dispatch. Keep this list in one place so a later key cannot be
   * added in only one caller.
   */
  public const RESERVED_IDENTITY_KEYS = [
    'user',
    'uid',
    'principal',
    'tenant',
    'tenant_id',
    'act',
    'on_behalf_of',
  ];

  /**
   * Constructs a frozen context.
   *
   * @param string $subject
   *   Token subject (sub). The original human principal when act is
   *   present.
   * @param string $clientId
   *   OAuth client id / authorized party.
   * @param string $azp
   *   Authorized-party claim; falls back to client id.
   * @param list<string> $scopes
   *   Granted scope names from the token.
   * @param string $tenant
   *   Tenant claim (DEV-839). Empty when the token omitted it.
   * @param list<string> $actChain
   *   RFC 8693 act delegation chain, outermost actor first. Empty when
   *   the token has no act claim.
   * @param bool $network
   *   TRUE when this context was built for a network call.
   */
  public function __construct(
    private string $subject,
    private string $clientId,
    private string $azp,
    private array $scopes,
    private string $tenant,
    private array $actChain,
    private bool $network,
  ) {}

  /**
   * Token subject.
   */
  public function subject(): string {
    return $this->subject;
  }

  /**
   * OAuth client id.
   */
  public function clientId(): string {
    return $this->clientId;
  }

  /**
   * Authorized party (azp), or the client id when azp was absent.
   */
  public function azp(): string {
    return $this->azp;
  }

  /**
   * Granted scopes.
   *
   * @return list<string>
   *   Scope names.
   */
  public function scopes(): array {
    return $this->scopes;
  }

  /**
   * Token-derived tenant, or '' when the claim was missing.
   */
  public function tenant(): string {
    return $this->tenant;
  }

  /**
   * Delegation chain from the act claim.
   *
   * @return list<string>
   *   Actor subjects, outermost first.
   */
  public function actChain(): array {
    return $this->actChain;
  }

  /**
   * Whether this context was built for a network call.
   */
  public function isNetwork(): bool {
    return $this->network;
  }

  /**
   * Reserved identity keys present on a top-level argument map.
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   *
   * @return list<string>
   *   Matching reserved keys, in the order they appear in the constant.
   */
  public static function reservedKeysIn(array $arguments): array {
    $found = [];
    $incoming = [];
    foreach (array_keys($arguments) as $key) {
      $incoming[strtolower((string) $key)] = (string) $key;
    }
    foreach (self::RESERVED_IDENTITY_KEYS as $reserved) {
      if (isset($incoming[$reserved])) {
        $found[] = $incoming[$reserved];
      }
    }
    return $found;
  }

}
