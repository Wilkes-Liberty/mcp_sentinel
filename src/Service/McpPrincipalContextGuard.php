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
   * Whether reserved-key and principal denies are enforced.
   */
  private bool $required = TRUE;

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

}
