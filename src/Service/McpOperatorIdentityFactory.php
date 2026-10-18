<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;

/**
 * Resolves a verified Paladin operator identity (DEV-986).
 *
 * Drush kill-switch commands take identity from a Paladin token:
 * iss|sub after introspection. A request-sealed principal is not
 * a Drush identity. Drupal uid and the OS user are not identity.
 * OS user and SUDO_USER are advisory audit metadata only. Fail
 * closed when no token is provided.
 */
final class McpOperatorIdentityFactory {

  /**
   * PHPUnit-only: form a Paladin identity when no token was provided.
   */
  public const WEAKEN_SKIP_TOKEN = 'skip_token';

  /**
   * Test-only weaken flags. Empty in production.
   *
   * @var array<string, true>
   */
  private array $weakenForTest = [];

  /**
   * PHPUnit-only process euid. NULL uses posix_geteuid().
   */
  private ?int $euidForTest = NULL;

  /**
   * PHPUnit-only process user name. NULL uses posix_getpwuid().
   */
  private ?string $processUserForTest = NULL;

  /**
   * Constructs the resolver.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPaladinIntrospection $introspection
   *   Paladin token introspection.
   */
  public function __construct(
    private readonly McpPaladinIntrospection $introspection,
  ) {}

  /**
   * Identity from a Paladin access token.
   *
   * A non-empty token is introspected and becomes paladin:iss|sub.
   * Without a token the command is refused. A request-sealed
   * principal is not a Drush identity. Drupal uid is not consulted.
   *
   * @param string $token
   *   Paladin access token, or empty when none was provided.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When no verified identity can be formed.
   */
  public function fromPaladinToken(string $token = ''): McpOperatorIdentity {
    $token = trim($token);
    if ($token !== '') {
      return $this->introspection->activeIdentity($token);
    }
    if ($this->weakened(self::WEAKEN_SKIP_TOKEN)) {
      return McpOperatorIdentity::paladin('https://idp.example/realms/agents|weakened-skip-token');
    }
    throw new McpKillSwitchException(
      McpKillSwitchException::MISSING_TOKEN,
      'A Paladin access token is required.',
    );
  }

  /**
   * OS process fields for audit rows. Never used as identity.
   *
   * @return array<string, string>
   *   euid, process user, and SUDO_USER when present.
   */
  public function advisoryProcessMetadata(): array {
    try {
      $euid = $this->effectiveUid();
    }
    catch (McpKillSwitchException) {
      return [
        'os_euid' => '',
        'os_user' => '',
        'sudo_user' => $this->sudoUser(),
      ];
    }
    return [
      'os_euid' => (string) $euid,
      'os_user' => $this->processUserName($euid),
      'sudo_user' => $this->sudoUser(),
    ];
  }

  /**
   * PHPUnit-only process identity for advisory audit metadata.
   *
   * @param int $euid
   *   Effective uid to report.
   * @param string $userName
   *   Process user name to report.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function setProcessIdentityForTest(int $euid, string $userName = ''): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Process identity can be injected only under PHPUnit.',
      );
    }
    $this->euidForTest = $euid;
    $this->processUserForTest = $userName;
  }

  /**
   * PHPUnit-only injection that disables a token refusal.
   *
   * @param string $flag
   *   One of the WEAKEN_* constants.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function weakenForTest(string $flag): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Operator-identity weaken flags can be set only under PHPUnit.',
      );
    }
    $this->weakenForTest[$flag] = TRUE;
  }

  /**
   * Effective uid of this process, or the PHPUnit override.
   */
  private function effectiveUid(): int {
    if ($this->euidForTest !== NULL) {
      return $this->euidForTest;
    }
    if (!function_exists('posix_geteuid')) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    return posix_geteuid();
  }

  /**
   * Process user name for the effective uid.
   */
  private function processUserName(int $euid): string {
    if ($this->processUserForTest !== NULL && $this->processUserForTest !== '') {
      return $this->processUserForTest;
    }
    if (!function_exists('posix_getpwuid')) {
      return '';
    }
    $info = posix_getpwuid($euid);
    if ($info === FALSE) {
      return '';
    }
    return $info['name'];
  }

  /**
   * SUDO_USER when present. Advisory only.
   */
  private function sudoUser(): string {
    $value = getenv('SUDO_USER');
    return is_string($value) ? $value : '';
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  private function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

}
