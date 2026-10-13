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
   * Compared after normalizeKey() (NFKC, strip \\p{Cf} and variation
   * selectors, fold case, drop `_` and `-`, Spoofchecker look-alikes).
   * Nested arrays and objects are walked. Keep this list in one place.
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
   * Token identity claims that a declared-input exception cannot exempt.
   */
  public const NEVER_EXEMPT_IDENTITY_KEYS = [
    'sub',
    'iss',
    'azp',
    'tenant',
    'tenant_id',
    'tenantId',
    'act',
    'principal',
    'on_behalf_of',
    'onBehalfOf',
    'client_id',
    'user_id',
    'userId',
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
   * NFKC, strip all Unicode format characters (\\p{Cf}, including
   * soft hyphen and direction marks) and variation selectors, strip
   * Unicode whitespace, fold case, then drop `_` and `-`. Look-alikes
   * use intl Spoofchecker (UTS #39) when ext-intl is available;
   * otherwise a non-ASCII key whose ASCII skeleton equals a reserved
   * key is treated as that reserved key.
   */
  public static function normalizeKey(string $name): string {
    $folded = self::foldKey($name);
    return self::canonicalReserved($folded, $name);
  }

  /**
   * NFKC + format/whitespace strip + case fold, without look-alike map.
   */
  public static function foldKey(string $name): string {
    $normalized = \Normalizer::normalize($name, \Normalizer::FORM_KC);
    if (!is_string($normalized)) {
      $normalized = $name;
    }
    $stripped = preg_replace('/\p{Cf}/u', '', $normalized);
    if (is_string($stripped)) {
      $normalized = $stripped;
    }
    $noVs = preg_replace(
      '/[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]/u',
      '',
      $normalized,
    );
    if (is_string($noVs)) {
      $normalized = $noVs;
    }
    $compact = preg_replace('/[\s\p{Z}]+/u', '', $normalized);
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
   * Maps a folded key onto a reserved name when it is a look-alike.
   *
   * Spoofchecker (UTS #39) when ext-intl is loaded. Otherwise only a
   * non-ASCII original whose ASCII skeleton equals a reserved fold is
   * rewritten. Documented so a JS twin can match.
   */
  private static function canonicalReserved(string $folded, string $original): string {
    $reservedFolds = [];
    foreach (self::RESERVED_IDENTITY_KEYS as $reserved) {
      $reservedFolds[self::foldKey($reserved)] = TRUE;
    }
    if (isset($reservedFolds[$folded])) {
      return $folded;
    }
    if (class_exists(\Spoofchecker::class)) {
      $checker = new \Spoofchecker();
      foreach (array_keys($reservedFolds) as $reserved) {
        if ($checker->areConfusable($folded, $reserved)
          || $checker->areConfusable($original, $reserved)) {
          return $reserved;
        }
      }
      return $folded;
    }
    if (preg_match('/[^\x00-\x7F]/u', $original) === 1) {
      $ascii = self::asciiSkeleton($folded);
      if (isset($reservedFolds[$ascii])) {
        return $ascii;
      }
    }
    return $folded;
  }

  /**
   * Best-effort ASCII skeleton when Spoofchecker is unavailable.
   */
  private static function asciiSkeleton(string $folded): string {
    if (function_exists('iconv')) {
      $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $folded);
      if (is_string($ascii) && $ascii !== '') {
        return strtolower($ascii);
      }
    }
    $stripped = preg_replace('/[^\x00-\x7F]/', '', $folded);
    return is_string($stripped) ? $stripped : $folded;
  }

  /**
   * Reserved identity keys present in an argument map.
   *
   * Walks nested arrays and objects. Matching uses normalizeKey().
   * Reported paths keep the caller's original casing. $topLevelExceptions
   * may skip declared schema input names at the top level only, never
   * NEVER_EXEMPT_IDENTITY_KEYS.
   *
   * @param array<string, mixed> $arguments
   *   Caller-supplied tool arguments.
   * @param list<string> $topLevelExceptions
   *   Declared input names that may carry a false-positive reserved word.
   *
   * @return list<string>
   *   Matching paths, grouped in RESERVED_IDENTITY_KEYS order.
   */
  public static function reservedKeysIn(
    array $arguments,
    array $topLevelExceptions = [],
  ): array {
    $reservedNorms = [];
    foreach (self::RESERVED_IDENTITY_KEYS as $reserved) {
      $reservedNorms[self::normalizeKey($reserved)] = TRUE;
    }
    $neverExempt = [];
    foreach (self::NEVER_EXEMPT_IDENTITY_KEYS as $reserved) {
      $neverExempt[self::normalizeKey($reserved)] = TRUE;
    }
    $exceptionNorms = [];
    foreach ($topLevelExceptions as $name) {
      $norm = self::normalizeKey((string) $name);
      if (!isset($neverExempt[$norm])) {
        $exceptionNorms[$norm] = TRUE;
      }
    }
    $foundByReserved = [];
    self::collectReservedKeys(
      $arguments,
      '',
      $foundByReserved,
      $reservedNorms,
      $exceptionNorms,
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
   * @param array<string, true> $exceptionNorms
   *   Top-level declared-input exceptions.
   */
  private static function collectReservedKeys(
    array $arguments,
    string $prefix,
    array &$foundByReserved,
    array $reservedNorms,
    array $exceptionNorms,
  ): void {
    foreach ($arguments as $key => $value) {
      $name = (string) $key;
      $path = $prefix === '' ? $name : $prefix . '.' . $name;
      $normalized = self::normalizeKey($name);
      $exempt = $prefix === '' && isset($exceptionNorms[$normalized]);
      if (isset($reservedNorms[$normalized]) && !$exempt) {
        $foundByReserved[$normalized][] = $path;
      }
      $nested = self::nestedMap($value);
      if ($nested !== NULL) {
        self::collectReservedKeys(
          $nested,
          $path,
          $foundByReserved,
          $reservedNorms,
          [],
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
