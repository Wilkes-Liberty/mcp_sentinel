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
 * Actor is the top-level act.sub when a delegation claim is present
 * (RFC 8693 current actor; nested act entries are prior actors and
 * do not change the key), otherwise azp. client_id is never an actor.
 * Only act.sub is read — never act.subject — so actChain() and the
 * key agree.
 *
 * Each part is capped at MAX_PART_LENGTH (256) characters. Unicode
 * whitespace-only parts (including NBSP), control characters, invalid
 * UTF-8, and '|' are rejected.
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
   * Maximum Unicode characters per iss, sub, or actor part.
   */
  public const MAX_PART_LENGTH = 256;

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
   *   Missing or invalid iss, sub, azp, or act.sub.
   */
  public static function fromClaims(array $claims): array {
    $iss = self::requirePart($claims, 'iss', McpPrincipalKeyException::MISSING_ISS);
    $sub = self::requirePart($claims, 'sub', McpPrincipalKeyException::MISSING_SUB);
    $actor = self::actorFromClaims($claims);
    foreach ([$iss, $sub, $actor] as $part) {
      self::assertSafePart($part);
    }
    return [
      'principalKey' => $iss . self::SEPARATOR . $sub . self::SEPARATOR . $actor,
      'humanKey' => $iss . self::SEPARATOR . $sub,
    ];
  }

  /**
   * Resolves the actor or fails closed.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   Missing act.sub or azp.
   */
  private static function actorFromClaims(array $claims): string {
    if (array_key_exists('act', $claims) && $claims['act'] !== NULL) {
      $actor = self::topLevelActSub($claims['act']);
      if ($actor === '') {
        throw new McpPrincipalKeyException(
          McpPrincipalKeyException::MISSING_ACT_SUB,
          'A delegation (act) claim requires a top-level act.sub.',
        );
      }
      return $actor;
    }
    return self::requirePart($claims, 'azp', McpPrincipalKeyException::MISSING_AZP);
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
   * Rejects '|', control characters, whitespace-only, and over-long parts.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the part cannot appear in a key.
   */
  private static function assertSafePart(string $part): void {
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
