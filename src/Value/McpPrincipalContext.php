<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Service\McpLookalikeChecker;
use Drupal\mcp_sentinel\Service\McpPrincipalKey;

/**
 * Immutable principal + tenant context from a validated token.
 *
 * Built at the request boundary (DEV-844 / DEV-839). Tools receive this
 * as a separate parameter and must never read identity or tenant from
 * tool arguments.
 *
 * Grant tables (mcp_admin_grant and related) are not an identity
 * source; this token-derived context is. mcp_admin_grant remains
 * live break-glass storage.
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
   * Request attribute that marks a kernel/PHPUnit fixture principal.
   *
   * Scope checks skip fixture and role-fallback sources, not an empty
   * Paladin scope list. The factory honours this marker only under
   * PHPUnit.
   */
  public const FIXTURE_ATTRIBUTE = 'mcp_sentinel.principal_fixture';

  /**
   * Request attribute set when readiness or the resolver took fallback.
   *
   * Positive provenance. An unmarked context is empty, not role
   * fallback.
   */
  public const FALLBACK_ATTRIBUTE = 'mcp_sentinel.role_fallback';

  /**
   * Context built from Paladin CLAIMS_ATTRIBUTE.
   */
  public const SOURCE_PALADIN = 'paladin';

  /**
   * Context built from the sealed-token auth provider.
   */
  public const SOURCE_SEALED_TOKEN = 'sealed_token';

  /**
   * Context built for a local-dev role-fallback session (no bearer).
   */
  public const SOURCE_ROLE_FALLBACK = 'role_fallback';

  /**
   * Context built for a kernel or PHPUnit fixture principal.
   */
  public const SOURCE_FIXTURE = 'fixture';

  /**
   * Empty deny-only or CLI context with no request claims.
   */
  public const SOURCE_EMPTY = 'empty';

  /**
   * Identity and tenant keys that must never appear in tool arguments.
   *
   * Compared after normalizeKey() (NFKC, strip \\p{Cf} and variation
   * selectors, fold case, drop `_` and `-`, Spoofchecker look-alike keys).
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
   * Owner/author field names that stay refused in entity `fields` maps.
   *
   * The author comes from the token principal, never tool arguments.
   * Also refuse any field whose definition is an entity_reference to
   * `user` (see McpEntityFieldReservedAllowlist).
   */
  public const OWNER_IDENTITY_FIELD_KEYS = [
    'uid',
    'owner',
    'revision_uid',
    'revision_user',
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
   * @param bool $sealedToken
   *   TRUE when the sealed-token auth provider produced the claims.
   * @param string $source
   *   Provenance of this context (Paladin, sealed token, role
   *   fallback, fixture, or empty).
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
    private bool $sealedToken = FALSE,
    private string $source = self::SOURCE_EMPTY,
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
   * TRUE when claims came from the sealed-token auth provider.
   *
   * Provenance, not the iss string. Paladin is the sole issuer
   * for governed tools (DEV-843).
   */
  public function fromSealedToken(): bool {
    return $this->sealedToken;
  }

  /**
   * Provenance of this context.
   */
  public function source(): string {
    return $this->source;
  }

  /**
   * TRUE when this context is the local-dev role-fallback path.
   */
  public function fromRoleFallback(): bool {
    return $this->source === self::SOURCE_ROLE_FALLBACK;
  }

  /**
   * TRUE when this context is a kernel or PHPUnit fixture.
   */
  public function fromFixture(): bool {
    return $this->source === self::SOURCE_FIXTURE;
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
   * Unicode whitespace, fold case, then drop `_` and `-`. A non-ASCII
   * key that intl Spoofchecker (UTS #39) finds confusable with a
   * reserved key is treated as that reserved key. ext-intl and
   * Spoofchecker are required; a missing checker fails closed
   * (lookalike_check_unavailable). There is no iconv fallback.
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
   * Maps a folded key onto a reserved name when it is a look-alike key.
   *
   * Pure-ASCII keys are compared by equality only. A key with any
   * non-ASCII character is run through Spoofchecker (UTS #39) against
   * each reserved fold. The checker and the reserved folds are built
   * once per process (McpLookalikeChecker). Documented so a JS twin
   * can match.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When Spoofchecker is unavailable (lookalike_check_unavailable).
   */
  private static function canonicalReserved(string $folded, string $original): string {
    $reservedFolds = McpLookalikeChecker::reservedFolds();
    if (isset($reservedFolds[$folded])) {
      return $folded;
    }
    if (preg_match('/[^\x00-\x7F]/', $original) !== 1
      && preg_match('/[^\x00-\x7F]/', $folded) !== 1) {
      return $folded;
    }
    $checker = McpLookalikeChecker::checker();
    foreach (array_keys($reservedFolds) as $reserved) {
      if ($checker->areConfusable($folded, $reserved)
        || $checker->areConfusable($original, $reserved)) {
        return $reserved;
      }
    }
    return $folded;
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
   * @param array<string, array{allow?: list<string>, refuse?: list<string>}> $nestedMapRules
   *   Per-map field-definition rules. Keys are top-level map input
   *   names (`fields`). allow: reserved content fields that may appear
   *   as immediate children. refuse: owner/author and user-reference
   *   field names. NEVER_EXEMPT_IDENTITY_KEYS are never allowed.
   *   config_set `data` must omit rules so it stays fully scanned.
   *
   * @return list<string>
   *   Matching paths, grouped in RESERVED_IDENTITY_KEYS order.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException
   *   When Spoofchecker is unavailable (lookalike_check_unavailable).
   */
  public static function reservedKeysIn(
    array $arguments,
    array $topLevelExceptions = [],
    array $nestedMapRules = [],
  ): array {
    McpLookalikeChecker::assertAvailable();
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
    $mapRules = [];
    foreach ($nestedMapRules as $mapName => $rules) {
      $allowNorms = [];
      foreach ($rules['allow'] ?? [] as $name) {
        $norm = self::normalizeKey((string) $name);
        if (!isset($neverExempt[$norm])) {
          $allowNorms[$norm] = TRUE;
        }
      }
      $refuseNorms = [];
      foreach ($rules['refuse'] ?? [] as $name) {
        $refuseNorms[self::normalizeKey((string) $name)] = TRUE;
      }
      $mapRules[(string) $mapName] = [
        'allow' => $allowNorms,
        'refuse' => $refuseNorms,
      ];
    }
    $foundByReserved = [];
    self::collectReservedKeys(
      $arguments,
      '',
      $foundByReserved,
      $reservedNorms,
      $exceptionNorms,
      $neverExempt,
      $mapRules,
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
    foreach (self::OWNER_IDENTITY_FIELD_KEYS as $owner) {
      $norm = self::normalizeKey($owner);
      if (isset($seenNorm[$norm]) || !isset($foundByReserved[$norm])) {
        continue;
      }
      $seenNorm[$norm] = TRUE;
      foreach ($foundByReserved[$norm] as $path) {
        $found[] = $path;
      }
    }
    foreach ($foundByReserved as $norm => $paths) {
      if (isset($seenNorm[$norm])) {
        continue;
      }
      $seenNorm[$norm] = TRUE;
      foreach ($paths as $path) {
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
   * @param array<string, true> $neverExempt
   *   Normalized never-exempt identity keys.
   * @param array<string, array{allow: array<string, true>, refuse: array<string, true>}> $mapRules
   *   Rules keyed by the parent map path (e.g. fields).
   */
  private static function collectReservedKeys(
    array $arguments,
    string $prefix,
    array &$foundByReserved,
    array $reservedNorms,
    array $exceptionNorms,
    array $neverExempt = [],
    array $mapRules = [],
  ): void {
    $rules = $mapRules[$prefix] ?? NULL;
    foreach ($arguments as $key => $value) {
      $name = (string) $key;
      $path = $prefix === '' ? $name : $prefix . '.' . $name;
      $normalized = self::normalizeKey($name);
      $isReserved = isset($reservedNorms[$normalized]);
      if ($rules !== NULL) {
        $forbidden = isset($neverExempt[$normalized])
          || isset($rules['refuse'][$normalized])
          || ($isReserved && !isset($rules['allow'][$normalized]));
        if ($forbidden) {
          $foundByReserved[$normalized][] = $path;
        }
      }
      else {
        $exempt = $prefix === '' && isset($exceptionNorms[$normalized]);
        if ($isReserved && !$exempt) {
          $foundByReserved[$normalized][] = $path;
        }
      }
      $nested = self::nestedMap($value);
      if ($nested !== NULL) {
        self::collectReservedKeys(
          $nested,
          $path,
          $foundByReserved,
          $reservedNorms,
          [],
          $neverExempt,
          $mapRules,
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
