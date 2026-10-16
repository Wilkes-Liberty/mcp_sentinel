<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * On/off switch for the principal-context dispatch guard.
 *
 * Production is always on. The only disable is an instance method that
 * throws unless PHPUnit's own constants are defined — no environment
 * variable can turn this off.
 */
final class McpPrincipalContextGuard {

  /**
   * PHPUnit-only: skip assertNotKilled() so a kill deny test can go red.
   */
  public const WEAKEN_SKIP_KILL = 'skip_kill';

  /**
   * PHPUnit-only: skip assertScopesAllowed() so a scope deny test can go red.
   */
  public const WEAKEN_SKIP_SCOPE = 'skip_scope';

  /**
   * Whether reserved-key and principal denies are enforced.
   */
  private bool $required = TRUE;

  /**
   * Test-only weaken flags. Empty in production.
   *
   * @var array<string, true>
   */
  private array $weakenForTest = [];

  /**
   * Whether reserved-key and missing-principal denies are enforced.
   */
  public function required(): bool {
    return $this->required;
  }

  /**
   * Test-only injection that restores pre-DEV-844 admission.
   *
   * Impossible outside the PHPUnit process: the runner's autoload
   * constants are required. No getenv() path exists.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function disableForTest(): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Principal-context guard can be disabled only under PHPUnit.',
      );
    }
    $this->required = FALSE;
  }

  /**
   * PHPUnit-only injection that disables one dispatcher check.
   *
   * Impossible outside the PHPUnit process. Used so a kill-only or
   * scope-only red run can fail without turning the whole guard off.
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
        'Principal-context weaken flags can be set only under PHPUnit.',
      );
    }
    $this->weakenForTest[$flag] = TRUE;
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  public function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

}
