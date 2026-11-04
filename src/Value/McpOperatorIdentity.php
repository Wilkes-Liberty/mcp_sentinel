<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Service\McpPrincipalKey;

/**
 * Verified operator identity for the two-person kill rule.
 *
 * Drupal uid is never this value. Paladin is iss|sub from a verified
 * token. Distinct operators compare iss|sub and mapped Drupal uids.
 * Leftover Drush-kind rows are not a verified identity. Storage ids
 * of different kinds never compare equal.
 */
final readonly class McpOperatorIdentity {

  /**
   * Paladin human key (iss|sub).
   */
  public const KIND_PALADIN = 'paladin';

  /**
   * Leftover Drush assertion fingerprint. Not a verified identity.
   */
  public const KIND_DRUSH = 'drush';

  /**
   * Unverified Drupal uid. PHPUnit-only. Never a production identity.
   *
   * @internal
   */
  public const KIND_UID = 'uid';

  /**
   * Worker or update-hook actor. Not a verified operator.
   */
  public const KIND_SYSTEM = 'system';

  /**
   * Constructs a verified or test-only identity.
   *
   * @param string $kind
   *   Paladin, leftover drush, system, or uid.
   * @param string $id
   *   Canonical human key, leftover fingerprint, or Drupal uid.
   */
  private function __construct(
    public string $kind,
    public string $id,
  ) {}

  /**
   * Paladin operator: verified human key (iss|sub).
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   *   When the key fails the principal-key vector rules.
   */
  public static function paladin(string $humanKey): self {
    return new self(self::KIND_PALADIN, McpPrincipalKey::parseHumanKey($humanKey));
  }

  /**
   * System actor for worker and update-hook holds.
   */
  public static function system(): self {
    return new self(self::KIND_SYSTEM, 'worker');
  }

  /**
   * Drupal uid. PHPUnit-only. Never a production operator identity.
   *
   * @internal
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the uid is anonymous.
   */
  public static function fromDrupalUid(string $uid): self {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Drupal uid operator identities exist only under PHPUnit.',
      );
    }
    if ($uid === '' || $uid === '0') {
      throw new McpKillSwitchException(
        McpKillSwitchException::MISSING_OPERATOR,
        'An operator account is required.',
      );
    }
    return new self(self::KIND_UID, $uid);
  }

  /**
   * Durable id stored on kill-block and audit rows.
   */
  public function storageId(): string {
    if ($this->kind === self::KIND_SYSTEM) {
      return 'system';
    }
    return $this->kind . ':' . $this->id;
  }

  /**
   * Whether this identity is a verified Paladin iss|sub.
   */
  public function isVerified(): bool {
    return $this->kind === self::KIND_PALADIN;
  }

  /**
   * Constant-time equality of kind and id.
   */
  public function equals(self $other): bool {
    return $this->kind === $other->kind
      && strlen($this->id) === strlen($other->id)
      && hash_equals($this->id, $other->id);
  }

}
