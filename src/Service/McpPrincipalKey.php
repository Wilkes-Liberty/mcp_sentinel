<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Shared principal-key formula for rate limits, budgets, and kill.
 *
 * Principal is iss|sub|actor. Human is iss|sub.
 *
 * Actor is namespaced by claim. A delegated token uses
 * ACT_PREFIX plus the top-level act.sub (RFC 8693 current
 * actor; nested act entries are prior actors and do not
 * change the key). A non-delegated token uses azp as-is so
 * stored iss|sub|azp keys stay valid. client_id is never an
 * actor. Only act.sub is read — never act.subject — so
 * actChain() and the key agree.
 *
 * An azp that already starts with ACT_PREFIX (any case) is
 * refused (actor_claim_collision) so it cannot occupy a
 * delegated actor slot. Same-token azp=X with act.sub=X is
 * allowed: the composed key is iss|sub|act:X, which is not
 * the azp-only key iss|sub|X. Audit and stored principal_key
 * identity stay separated. Kill-switch and webhook-hold
 * lookup permanently treat the two spellings as one stop
 * (over-inclusive only; never fail open). See
 * enforcementAliases().
 *
 * Each raw claim part is capped at MAX_PART_LENGTH (256)
 * characters. For a delegated token the cap applies to
 * act.sub before ACT_PREFIX is added, so a 256-character
 * act.sub stays accepted; the stored actor may be 260
 * characters. A raw part over 256 still fails closed.
 * Unicode whitespace-only parts (including NBSP), control
 * characters, invalid UTF-8, and '|' are rejected.
 *
 * Language-neutral vectors: tests/fixtures/principal-key-vectors.json.
 * The Node connector tests a JS twin against the same file.
 */
final class McpPrincipalKey {

  /**
   * Segment separator. Claim values must not contain this character.
   */
  public const SEPARATOR = '|';

  /**
   * Maximum Unicode characters per raw iss, sub, azp, or act.sub.
   */
  public const MAX_PART_LENGTH = 256;

  /**
   * Prefix on a delegated actor so act.sub cannot occupy an azp slot.
   *
   * Non-delegated keys keep the raw azp value. This prefix is not a
   * JWT claim; it is only the stored/looked-up actor part. Product
   * code always emits this exact lowercase spelling.
   */
  public const ACT_PREFIX = 'act:';

  /**
   * Path of the shared vector file, relative to the module root.
   */
  public const VECTORS_FILE = 'tests/fixtures/principal-key-vectors.json';

  /**
   * Constructs the current-request accessor.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory $factory
   *   Token-derived context factory.
   */
  public function __construct(
    private readonly McpPrincipalContextFactory $factory,
  ) {}

  /**
   * Shared principal key: iss|sub|actor.
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext|null $ctx
   *   Frozen context, or NULL to use the current request.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the token cannot compose a key.
   */
  public function principalKey(?McpPrincipalContext $ctx = NULL): string {
    return self::formatPrincipal($ctx ?? $this->factory->fromCurrentRequest());
  }

  /**
   * Human principal key: iss|sub (no actor).
   *
   * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext|null $ctx
   *   Frozen context, or NULL to use the current request.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the token cannot compose a key.
   */
  public function humanKey(?McpPrincipalContext $ctx = NULL): string {
    return self::formatHuman($ctx ?? $this->factory->fromCurrentRequest());
  }

  /**
   * Formats iss|sub|actor from a frozen context.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the token cannot compose a key.
   */
  public static function formatPrincipal(McpPrincipalContext $ctx): string {
    return self::fromClaims($ctx->keyClaims())['principalKey'];
  }

  /**
   * Formats iss|sub from a frozen context.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the token cannot compose a key.
   */
  public static function formatHuman(McpPrincipalContext $ctx): string {
    return self::fromClaims($ctx->keyClaims())['humanKey'];
  }

  /**
   * Composes keys from JWT-shaped claims, or fails closed.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims (iss, sub, azp, act).
   *
   * @return array{principalKey: string, humanKey: string}
   *   Both keys when the claims are complete and separator-safe.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   Missing or invalid iss, sub, azp, or act.sub, or an actor
   *   claim collision.
   */
  public static function fromClaims(array $claims): array {
    $iss = self::requirePart($claims, 'iss', McpPrincipalKeyException::MISSING_ISS);
    $sub = self::requirePart($claims, 'sub', McpPrincipalKeyException::MISSING_SUB);
    $actor = self::actorFromClaims($claims);
    foreach ([$iss, $sub] as $part) {
      self::assertSafePart($part);
    }
    // Delegated actors already passed assertSafePart on the
    // raw act.sub. Re-checking the prefixed string would
    // refuse a 253-to-256-character act.sub (part_too_long)
    // that was accepted before the prefix existed.
    if (!self::actorHasActPrefix($actor)) {
      self::assertSafePart($actor);
    }
    return [
      'principalKey' => $iss . self::SEPARATOR . $sub . self::SEPARATOR . $actor,
      'humanKey' => $iss . self::SEPARATOR . $sub,
    ];
  }

  /**
   * Resolves the actor or fails closed.
   *
   * Delegated actors are prefixed. Authorized-party stays
   * unprefixed so existing non-delegated principal keys stay
   * valid. An azp that already starts with ACT_PREFIX (any
   * case) is refused so it cannot occupy a delegated slot.
   * Same-token azp=X with act.sub=X is not a collision: the
   * delegated key is act:X.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   Missing act.sub or azp, or an actor claim collision.
   */
  private static function actorFromClaims(array $claims): string {
    $azp = $claims['azp'] ?? NULL;
    $azp = is_string($azp) ? $azp : '';
    if ($azp !== '' && self::actorHasActPrefix($azp)) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::ACTOR_CLAIM_COLLISION,
        'Authorized-party (azp) must not use the act.sub actor prefix.',
      );
    }
    if (array_key_exists('act', $claims) && $claims['act'] !== NULL) {
      $actor = self::topLevelActSub($claims['act']);
      if ($actor === '') {
        throw new McpPrincipalKeyException(
          McpPrincipalKeyException::MISSING_ACT_SUB,
          'A delegation (act) claim requires a top-level act.sub.',
        );
      }
      // Cap and reject the raw claim before prefixing so
      // whitespace-only act.sub cannot hide behind ACT_PREFIX
      // and a 253-to-256-character act.sub stays accepted.
      self::assertSafePart($actor);
      return self::ACT_PREFIX . $actor;
    }
    return self::requirePart($claims, 'azp', McpPrincipalKeyException::MISSING_AZP);
  }

  /**
   * Whether an actor part uses the delegated prefix (any case).
   *
   * Product code always emits ACT_PREFIX. The case-insensitive
   * check stops an authorized-party of ACT:X occupying the
   * delegated slot.
   */
  public static function actorHasActPrefix(string $actor): bool {
    $length = strlen(self::ACT_PREFIX);
    return strlen($actor) >= $length
      && strncasecmp($actor, self::ACT_PREFIX, $length) === 0;
  }

  /**
   * Canonical delegated actor spelling (lowercase prefix).
   *
   * Operator-supplied ACT:X becomes act:X so kill rows and
   * parsePrincipalKey never store a mixed-case prefix.
   */
  public static function canonicalActActor(string $actor): string {
    if (!self::actorHasActPrefix($actor)) {
      return $actor;
    }
    return self::ACT_PREFIX . substr($actor, strlen(self::ACT_PREFIX));
  }

  /**
   * Kill and webhook lookup spellings for one principal key.
   *
   * Permanent bidirectional aliases for every lookup, not a
   * time-bounded upgrade. A stop or webhook row stored as
   * iss|sub|X also matches iss|sub|act:X and the reverse. A
   * new iss|sub|act:X stop therefore also refuses a
   * non-delegated azp=X token, and a new iss|sub|X stop also
   * refuses a delegated act.sub=X token, for as long as this
   * module is installed. That is over-inclusive on purpose
   * (over-block only, never under-block): stored X cannot be
   * proven to have been azp versus act.sub. It does not match
   * a different iss or sub, and it strips only one prefix
   * (iss|sub|act:act:X pairs with iss|sub|act:X, not with
   * iss|sub|X). Operator-supplied ACT:X is canonicalized to
   * act:X before pairing. holdMatching uses this same set, so
   * a stop of iss|sub|act:X does not select a pending row
   * stored as iss|sub|act:act:X. Send-time shouldHoldRow
   * still catches that row: the stored key's aliases include
   * iss|sub|act:X.
   *
   * Audit and stored principal_key identity stay separated.
   * No update hook: stored X is ambiguous. Dual-match is the
   * permanent smallest fail-closed pairing. Rolling this
   * module back restores exact-match lookup.
   *
   * @return list<string>
   *   Canonical key plus its actor-slot twin, when the key
   *   is iss|sub|actor. Otherwise the input only.
   */
  public static function enforcementAliases(string $principalKey): array {
    if ($principalKey === '') {
      return [];
    }
    if (!mb_check_encoding($principalKey, 'UTF-8')
      || substr_count($principalKey, self::SEPARATOR) !== 2) {
      return [$principalKey];
    }
    [$iss, $sub, $actor] = explode(self::SEPARATOR, $principalKey, 3);
    $canonicalActor = self::canonicalActActor($actor);
    $canonical = $iss . self::SEPARATOR . $sub . self::SEPARATOR . $canonicalActor;
    $aliases = [$canonical];
    if (self::actorHasActPrefix($canonicalActor)) {
      $remainder = substr($canonicalActor, strlen(self::ACT_PREFIX));
      if ($remainder !== '') {
        $aliases[] = $iss . self::SEPARATOR . $sub . self::SEPARATOR . $remainder;
      }
    }
    elseif ($canonicalActor !== '') {
      $aliases[] = $iss . self::SEPARATOR . $sub . self::SEPARATOR
        . self::ACT_PREFIX . $canonicalActor;
    }
    return array_values(array_unique($aliases));
  }

  /**
   * Top-level act.sub only. Nested act and act.subject are ignored.
   */
  public static function topLevelActSub(mixed $act): string {
    if (!is_array($act) || array_is_list($act)) {
      return '';
    }
    $sub = $act['sub'] ?? NULL;
    return is_string($sub) ? $sub : '';
  }

  /**
   * Non-empty string claim, or throws the named reason.
   *
   * @param array<string, mixed> $claims
   *   Claims.
   * @param string $name
   *   Claim name.
   * @param string $missing
   *   Reason when the claim is absent or not a string.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the named claim is missing.
   */
  private static function requirePart(
    array $claims,
    string $name,
    string $missing,
  ): string {
    $value = $claims[$name] ?? NULL;
    if (!is_string($value) || $value === '') {
      throw new McpPrincipalKeyException(
        $missing,
        'Principal key requires a ' . $name . ' claim.',
      );
    }
    return $value;
  }

  /**
   * Canonical iss|sub|actor from an operator-supplied principal key.
   *
   * Uses the same part rules and error codes as fromClaims() /
   * tests/fixtures/principal-key-vectors.json. Extra '|' is
   * invalid_separator; too few parts is invalid_part.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the key cannot be composed.
   */
  public static function parsePrincipalKey(string $key): string {
    $parts = self::splitKey($key, 2);
    $missing = [
      McpPrincipalKeyException::MISSING_ISS,
      McpPrincipalKeyException::MISSING_SUB,
      McpPrincipalKeyException::MISSING_AZP,
    ];
    $names = ['iss', 'sub', 'actor'];
    foreach ($parts as $i => $part) {
      if ($part === '') {
        throw new McpPrincipalKeyException(
          $missing[$i],
          'Principal key requires a ' . $names[$i] . ' claim.',
        );
      }
      // Apply the 256 cap to the raw act.sub when the actor
      // already carries ACT_PREFIX, matching fromClaims().
      if ($i === 2 && self::actorHasActPrefix($part)) {
        self::assertSafePart(substr($part, strlen(self::ACT_PREFIX)));
        continue;
      }
      self::assertSafePart($part);
    }
    $parts[2] = self::canonicalActActor($parts[2]);
    return implode(self::SEPARATOR, $parts);
  }

  /**
   * Canonical iss|sub from an operator-supplied human key.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the key cannot be composed.
   */
  public static function parseHumanKey(string $key): string {
    $parts = self::splitKey($key, 1);
    $missing = [
      McpPrincipalKeyException::MISSING_ISS,
      McpPrincipalKeyException::MISSING_SUB,
    ];
    $names = ['iss', 'sub'];
    foreach ($parts as $i => $part) {
      if ($part === '') {
        throw new McpPrincipalKeyException(
          $missing[$i],
          'Principal key requires a ' . $names[$i] . ' claim.',
        );
      }
      self::assertSafePart($part);
    }
    return implode(self::SEPARATOR, $parts);
  }

  /**
   * Splits a composed key into the expected number of parts.
   *
   * @return list<string>
   *   Parts.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When UTF-8 is invalid or the separator count is wrong.
   */
  private static function splitKey(string $key, int $separators): array {
    if (!mb_check_encoding($key, 'UTF-8')) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_UTF8,
        'Principal-key claims must be valid UTF-8.',
      );
    }
    $found = substr_count($key, self::SEPARATOR);
    if ($found > $separators) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_SEPARATOR,
        'Principal-key claims must not contain "|".',
      );
    }
    if ($found < $separators) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_PART,
        'The kill selector does not match the principal-key shape.',
      );
    }
    return explode(self::SEPARATOR, $key);
  }

  /**
   * Rejects '|', control characters, whitespace-only, and over-long parts.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the part cannot appear in a key.
   */
  public static function assertSafePart(string $part): void {
    if (!mb_check_encoding($part, 'UTF-8')) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_UTF8,
        'Principal-key claims must be valid UTF-8.',
      );
    }
    if (str_contains($part, self::SEPARATOR)) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_SEPARATOR,
        'Principal-key claims must not contain "|".',
      );
    }
    if (preg_match('/^[\s\p{Z}]*$/u', $part) !== 0) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_PART,
        'Principal-key claims must not be whitespace-only.',
      );
    }
    if (preg_match('/\p{C}/u', $part) !== 0) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::INVALID_PART,
        'Principal-key claims must not contain control characters.',
      );
    }
    if (mb_strlen($part, 'UTF-8') > self::MAX_PART_LENGTH) {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::PART_TOO_LONG,
        'Principal-key claims must be at most '
        . (string) self::MAX_PART_LENGTH
        . ' characters per part.',
      );
    }
  }

}
