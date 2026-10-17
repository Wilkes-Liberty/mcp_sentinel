<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\PrivateKey;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;

/**
 * Resolves a verified operator identity (DEV-986).
 *
 * Drush kill commands take identity from a Paladin token: iss|sub
 * after introspection. The OS-user HMAC is off unless
 * settings.php sets mcp_sentinel.allow_drush_os_assertion. Config
 * cannot turn that path on. Even then, euid 0 and the web-server
 * user are refused. The login name and USER are not inputs.
 * currentUser / --uid is never used. OS user and SUDO_USER are
 * advisory audit metadata only. Fail closed when no verified
 * identity exists.
 */
final class McpOperatorIdentityFactory {

  /**
   * Settings.php flag that enables the OS-user HMAC fallback.
   */
  public const SETTING_ALLOW_OS_ASSERTION = 'mcp_sentinel.allow_drush_os_assertion';

  /**
   * Settings.php pin for the web-server account name.
   */
  public const SETTING_WEB_SERVER_USER = 'mcp_sentinel.web_server_user';

  /**
   * PHPUnit-only: allow euid 0 on the OS-assertion path.
   */
  public const WEAKEN_SKIP_EUID_ZERO = 'skip_euid_zero';

  /**
   * PHPUnit-only: allow the web-server user on the OS-assertion path.
   */
  public const WEAKEN_SKIP_WEB_SERVER_USER = 'skip_web_server_user';

  /**
   * Well-known web-server account names. Always refused.
   */
  private const WEB_SERVER_USERS = [
    'www-data',
    'apache',
    'nginx',
    'httpd',
    'nobody',
  ];

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
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Sealed Paladin principal, when the request has one.
   * @param \Drupal\Core\PrivateKey $privateKey
   *   Site key for the Drush assertion HMAC.
   * @param \Drupal\Core\Site\Settings $settings
   *   OS-assertion flag and web-server user pin.
   * @param \Drupal\mcp_sentinel\Service\McpPaladinIntrospection $introspection
   *   Paladin token introspection.
   */
  public function __construct(
    private readonly McpPrincipalContextHolder $holder,
    private readonly PrivateKey $privateKey,
    private readonly Settings $settings,
    private readonly McpPaladinIntrospection $introspection,
  ) {}

  /**
   * Identity for a Drush kill-switch command.
   *
   * A non-empty token is introspected and becomes paladin:iss|sub.
   * Without a token, the OS HMAC is used only when settings.php
   * enables it. Drupal uid is not consulted.
   *
   * @param string $token
   *   Paladin access token, or empty when none was provided.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When no verified identity can be formed.
   */
  public function forDrushCommand(string $token = ''): McpOperatorIdentity {
    $token = trim($token);
    if ($token !== '') {
      return $this->introspection->activeIdentity($token);
    }
    if (!$this->osAssertionEnabled()) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    return $this->fromDrushAssertion();
  }

  /**
   * Paladin human key from the sealed principal, or NULL.
   */
  public function fromVerifiedPrincipal(): ?McpOperatorIdentity {
    $ctx = $this->holder->get();
    if ($ctx === NULL) {
      return NULL;
    }
    try {
      $keys = McpPrincipalKey::fromClaims($ctx->keyClaims());
      return McpOperatorIdentity::paladin($keys['humanKey']);
    }
    catch (McpPrincipalKeyException | McpKillSwitchException) {
      return NULL;
    }
  }

  /**
   * HMAC of the OS effective uid. Independent of --uid / currentUser.
   *
   * Off unless settings.php enables it. euid 0 and the web-server
   * user are refused. A changed USER variable does not change this.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the OS assertion is disabled, the process is root or
   *   the web-server user, or the site key is missing.
   */
  public function fromDrushAssertion(): McpOperatorIdentity {
    if (!$this->osAssertionEnabled()) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $euid = $this->effectiveUid();
    $name = $this->processUserName($euid);
    if ($euid === 0 && !$this->weakened(self::WEAKEN_SKIP_EUID_ZERO)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    if ($this->isForbiddenProcessUser($name)
      && !$this->weakened(self::WEAKEN_SKIP_WEB_SERVER_USER)) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $secret = $this->privateKey->get();
    if ($secret === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $fingerprint = hash_hmac('sha256', 'uid:' . (string) $euid, $secret);
    return McpOperatorIdentity::drushAssertion($fingerprint);
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
   * PHPUnit-only process identity for same-euid / distinct-token tests.
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
   * PHPUnit-only injection that disables an OS-assertion refusal.
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
   * Whether settings.php enabled the OS-user HMAC.
   */
  private function osAssertionEnabled(): bool {
    return $this->settings->get(self::SETTING_ALLOW_OS_ASSERTION) === TRUE;
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
   * Root is handled separately. This is the web-server account.
   */
  private function isForbiddenProcessUser(string $name): bool {
    if ($name === '') {
      return TRUE;
    }
    $pinned = $this->settings->get(self::SETTING_WEB_SERVER_USER, 'www-data');
    $forbidden = self::WEB_SERVER_USERS;
    if (is_string($pinned) && $pinned !== '') {
      $forbidden[] = $pinned;
    }
    return in_array($name, $forbidden, TRUE);
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  private function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

}
