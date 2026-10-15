<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Enum\McpKillSelectorType;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Service\McpPrincipalKey;

/**
 * One kill-registry target: principal_key, human_key, or tenant.
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
   * Principal-key selector.
   */
  public static function principalKey(string $key): self {
    self::assertKeyShape($key, 2);
    return new self(McpKillSelectorType::PrincipalKey, $key);
  }

  /**
   * Human-key selector (all agents of this person).
   */
  public static function humanKey(string $key): self {
    self::assertKeyShape($key, 1);
    return new self(McpKillSelectorType::HumanKey, $key);
  }

  /**
   * Tenant-wide selector.
   */
  public static function tenant(string $tenant): self {
    return new self(McpKillSelectorType::Tenant, $tenant);
  }

  /**
   * Rejects a key that does not have the expected number of '|'.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private static function assertKeyShape(string $key, int $separators): void {
    $parts = explode(McpPrincipalKey::SEPARATOR, $key);
    if (count($parts) !== $separators + 1) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_SELECTOR,
        'The kill selector does not match the principal-key shape.',
      );
    }
    foreach ($parts as $part) {
      if ($part === '') {
        throw new McpKillSwitchException(
          McpKillSwitchException::INVALID_SELECTOR,
          'The kill selector has an empty part.',
        );
      }
    }
  }

}
