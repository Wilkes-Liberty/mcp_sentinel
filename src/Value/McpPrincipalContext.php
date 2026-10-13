<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Service\McpPrincipalKey;

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
   * Compared after normalizeKey() (NFKC, strip whitespace and
   * zero-width, fold case, drop `_` and `-`). Nested arrays and
   * objects are walked. Keep this list in one place.
   */
  public const RESERVED_IDENTITY_KEYS = [
    'user',
    'uid',
    'principal',
    'tenant',
    'tenant_id',
    'tenantId',
    'act',
    'on_behalf_of',
    'onBehalfOf',
    'sub',
    'iss',
    'azp',
    'client_id',
    'user_id',
    'userId',
    'actor',
    'scope',
    'scopes',
    'subject',
  ];

  /**
   * Constructs a frozen context.
   *
   * @param string $issuer
   *   Token issuer (iss).
   * @param string $subject
   *   Token subject (sub). The original human principal when act is
   *   present.
   * @param string $clientId
   *   OAuth client id / authorized party.
   * @param string $azp
   *   Authorized-party claim. Never a client_id fallback.
   * @param list<string> $scopes
   *   Granted scope names from the token.
   * @param string $tenant
   *   Tenant claim (DEV-839). Empty when the token omitted it.
   * @param list<string> $actChain
   *   RFC 8693 act delegation chain, outermost actor first. Empty when
   *   the token has no act claim.
   * @param bool $network
   *   TRUE when this context was built for a network call.
   * @param array<string, mixed> $keyClaims
   *   Token claims used to compose principal keys (iss, sub, azp,
   *   act). Empty when the context was built without a token.
   */
  public function __construct(
    private string $issuer,
    private string $subject,
    private string $clientId,
    private string $azp,
    private array $scopes,
    private string $tenant,
    private array $actChain,
    private bool $network,
    private array $keyClaims = [],
  ) {}

  /**
   * Token issuer (iss).
   */
  public function issuer(): string {
    return $this->issuer;
  }

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
   * Authorized party (azp). Empty when the token omitted it.
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
   * Token claims used to compose the shared principal key.
   *
   * Only the claims the factory stored from the token — never a
   * uid or client_id fallback.
   *
   * @return array<string, mixed>
   *   JWT-shaped iss/sub/azp/act map for McpPrincipalKey::fromClaims().
   */
  public function keyClaims(): array {
    return $this->keyClaims;
  }

  /**
   * Shared principal key: iss|sub|actor.
   *
   * Actor is the top-level act.sub when a delegation claim is present,
   * otherwise azp. Fails closed when the token cannot compose a key.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   Missing iss/sub/azp/act.sub, or a '|' in a segment.
   */
  public function principalKey(): string {
    return McpPrincipalKey::fromClaims($this->keyClaims())['principalKey'];
  }

  /**
   * Human principal key: iss|sub (no actor).
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   Missing iss/sub, or a '|' in a segment.
   */
  public function humanKey(): string {
    return McpPrincipalKey::fromClaims($this->keyClaims())['humanKey'];
  }

  /**
   * Normalizes an argument key for reserved-identity matching.
   *
   * NFKC, strip whitespace and zero-width characters, fold case,
   * then drop `_` and `-`. `onBehalfOf`, `on_behalf_of`, and
   * `ON-BEHALF-OF` all become `onbehalfof`.
   */
  public static function normalizeKey(string $name): string {
    $normalized = \Normalizer::normalize($name, \Normalizer::FORM_KC);
    if (!is_string($normalized)) {
      $normalized = $name;
    }
    $stripped = preg_replace(
      '/[\x{200B}-\x{200D}\x{FEFF}\x{2060}]/u',
      '',
      $normalized,
    );
    if (is_string($stripped)) {
      $normalized = $stripped;
    }
    $compact = preg_replace('/\s+/u', '', $normalized);
    if (is_string($compact)) {
      $normalized = $compact;
    }
    return str_replace(
      ['_', '-'],
      '',
      mb_strtolower($normalized, 'UTF-8'),
    );
  }

  /**
   * Reserved identity keys present in an argument map.
   *
   * Walks nested arrays and objects. Matching uses normalizeKey().
   * Reported paths keep the caller's original casing.
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   *
   * @return list<string>
   *   Matching paths, grouped in RESERVED_IDENTITY_KEYS order.
   */
  public static function reservedKeysIn(array $arguments): array {
    $reservedNorms = [];
    foreach (self::RESERVED_IDENTITY_KEYS as $reserved) {
      $reservedNorms[self::normalizeKey($reserved)] = TRUE;
    }
    $foundByReserved = [];
    self::collectReservedKeys(
      $arguments,
      '',
      $foundByReserved,
      $reservedNorms,
    );
    $found = [];
    $seenNorm = [];
    foreach (self::RESERVED_IDENTITY_KEYS as $reserved) {
      $norm = self::normalizeKey($reserved);
      if (isset($seenNorm[$norm]) || !isset($foundByReserved[$norm])) {
        continue;
      }
      $seenNorm[$norm] = TRUE;
      foreach ($foundByReserved[$norm] as $path) {
        $found[] = $path;
      }
    }
    return $found;
  }

  /**
   * Collects reserved keys at every nesting depth.
   *
   * @param array<mixed> $arguments
   *   Argument map, nested list, or object vars.
   * @param string $prefix
   *   Dotted path to this map.
   * @param array<string, list<string>> $foundByReserved
   *   Accumulator keyed by the normalized reserved name.
   * @param array<string, true> $reservedNorms
   *   Normalized reserved names.
   */
  private static function collectReservedKeys(
    array $arguments,
    string $prefix,
    array &$foundByReserved,
    array $reservedNorms,
  ): void {
    foreach ($arguments as $key => $value) {
      $name = (string) $key;
      $path = $prefix === '' ? $name : $prefix . '.' . $name;
      $normalized = self::normalizeKey($name);
      if (isset($reservedNorms[$normalized])) {
        $foundByReserved[$normalized][] = $path;
      }
      $nested = self::nestedMap($value);
      if ($nested !== NULL) {
        self::collectReservedKeys(
          $nested,
          $path,
          $foundByReserved,
          $reservedNorms,
        );
      }
    }
  }

  /**
   * Nested array or object walked as a map, or NULL.
   *
   * @return array<mixed>|null
   *   Child map.
   */
  private static function nestedMap(mixed $value): ?array {
    if (is_array($value)) {
      return $value;
    }
    if ($value instanceof \stdClass) {
      return get_object_vars($value);
    }
    return NULL;
  }

}
