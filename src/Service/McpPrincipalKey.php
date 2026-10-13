<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;

/**
 * Shared principal-key formula for rate limits, budgets, and kill.
 *
 * Other code imports this service (or fromClaims()) instead of
 * assembling iss/sub/actor itself. The frozen context exposes the same
 * strings as principalKey() and humanKey().
 *
 *   principal = iss|sub|actor
 *   human     = iss|sub
 *
 * actor is the top-level act.sub when a delegation claim is present
 * (RFC 8693 current actor; nested act entries are prior actors and
 * do not change the key), otherwise azp. client_id is never an actor.
 * Missing iss, sub, azp (when no act), or act.sub (when act is
 * present) fails closed — no key. A '|' in iss, sub, or actor is
 * rejected so a claim cannot forge an extra segment.
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
   * This is the language-neutral entry the shared vector file drives.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims (iss, sub, azp, act).
   *
   * @return array{principalKey: string, humanKey: string}
   *   Both keys when the claims are complete and separator-safe.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   Missing iss, sub, azp, or act.sub, or an invalid separator.
   */
  public static function fromClaims(array $claims): array {
    $iss = self::stringClaim($claims, 'iss');
    if ($iss === '') {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::MISSING_ISS,
        'Principal key requires an iss claim.',
      );
    }
    $sub = self::stringClaim($claims, 'sub');
    if ($sub === '') {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::MISSING_SUB,
        'Principal key requires a sub claim.',
      );
    }
    $actor = self::actorFromClaims($claims);
    foreach ([$iss, $sub, $actor] as $part) {
      if (str_contains($part, self::SEPARATOR)) {
        throw new McpPrincipalKeyException(
          McpPrincipalKeyException::INVALID_SEPARATOR,
          'Principal-key claims must not contain "|".',
        );
      }
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
    $azp = self::stringClaim($claims, 'azp');
    if ($azp === '') {
      throw new McpPrincipalKeyException(
        McpPrincipalKeyException::MISSING_AZP,
        'Principal key requires azp when the token has no act claim.',
      );
    }
    return $azp;
  }

  /**
   * Top-level act.sub only. Nested act entries are prior actors.
   */
  private static function topLevelActSub(mixed $act): string {
    if (!is_array($act) || array_is_list($act)) {
      return '';
    }
    $sub = $act['sub'] ?? NULL;
    return is_string($sub) ? $sub : '';
  }

  /**
   * Non-empty string claim, or ''.
   *
   * @param array<string, mixed> $claims
   *   Claims.
   * @param string $name
   *   Claim name.
   */
  private static function stringClaim(array $claims, string $name): string {
    $value = $claims[$name] ?? NULL;
    return is_string($value) ? $value : '';
  }

}
