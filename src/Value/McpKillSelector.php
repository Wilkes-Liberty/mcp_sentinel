<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Enum\McpKillSelectorType;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Service\McpPrincipalKey;

/**
 * One kill-registry target: principal_key, human_key, or tenant.
 *
 * Principal and human keys are canonicalized with McpPrincipalKey
 * using the same rules and error codes as principal-key-vectors.json.
 */
final readonly class McpKillSelector {

  /**
   * Maximum stored selector length. Longer values are refused.
   */
  public const MAX_KEY_LENGTH = 770;

  /**
   * Constructs a validated selector.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpKillSelectorType $type
   *   Selector kind.
   * @param string $key
   *   The principal_key, human_key, or tenant value.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the key is empty, too long, or not UTF-8.
   */
  public function __construct(
    public McpKillSelectorType $type,
    public string $key,
  ) {
    if ($key === '' || !mb_check_encoding($key, 'UTF-8')) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'A kill selector must be a non-empty UTF-8 string.',
      );
    }
    if (mb_strlen($key, 'UTF-8') > self::MAX_KEY_LENGTH) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'A kill selector is longer than the stored column.',
      );
    }
  }

  /**
   * Stable hash used as the unique row key.
   */
  public function hash(): string {
    return hash('sha256', $this->type->value . "\0" . $this->key);
  }

  /**
   * Kill-registry hashes for a principal key and its actor-slot twin.
   *
   * Permanent pairing: every principal-key lookup includes
   * both spellings. Aliases that cannot be stored (empty or
   * longer than the column) are omitted; they cannot match a
   * row.
   *
   * @return list<string>
   *   Hashes to query.
   */
  public static function principalKeyLookupHashes(string $principalKey): array {
    $hashes = [];
    foreach (McpPrincipalKey::enforcementAliases($principalKey) as $alias) {
      try {
        $hashes[] = (new self(McpKillSelectorType::PrincipalKey, $alias))->hash();
      }
      catch (McpKillSwitchException) {
        // Dual-match can add act: to a 770-character
        // unprefixed key, producing a 774-character alias.
        // That spelling cannot be stored, so it cannot match
        // a row. Keep the unprefixed hash. fromClaims() and
        // parsePrincipalKey() already refuse an over-long
        // composed key, so a stored act: spelling never
        // reaches this catch.
      }
    }
    return $hashes;
  }

  /**
   * Principal-key selector (iss|sub|actor).
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the key fails the principal-key vector rules.
   */
  public static function principalKey(string $key): self {
    return new self(
      McpKillSelectorType::PrincipalKey,
      McpPrincipalKey::parsePrincipalKey($key),
    );
  }

  /**
   * Human-key selector (iss|sub: every agent of this person).
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the key fails the principal-key vector rules.
   */
  public static function humanKey(string $key): self {
    return new self(
      McpKillSelectorType::HumanKey,
      McpPrincipalKey::parseHumanKey($key),
    );
  }

  /**
   * Tenant-wide selector.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the tenant fails a principal-key part rule (same codes as
   *   tests/fixtures/principal-key-vectors.json).
   */
  public static function tenant(string $tenant): self {
    McpPrincipalKey::assertSafePart($tenant);
    return new self(McpKillSelectorType::Tenant, $tenant);
  }

}
