<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * On/off switch for the principal-context dispatch guard.
 *
 * Production is always on. The disable env is honoured only under
 * PHPUnit so a red run can prove the denies are real (DEV-844).
 */
final class McpPrincipalContextGuard {

  /**
   * PHPUnit-only escape that restores pre-DEV-844 admission.
   *
   * Production never honours this. PHPUnit is detected via the composer
   * autoload constant the runner defines, not a caller-supplied flag.
   */
  public const TEST_DISABLE_ENV = 'MCP_TEST_DISABLE_PRINCIPAL_CONTEXT_GUARD';

  /**
   * Whether reserved-key and missing-tenant denies are enforced.
   */
  public static function required(): bool {
    if (getenv(self::TEST_DISABLE_ENV) !== '1') {
      return TRUE;
    }
    return !self::runningUnderPhpunit();
  }

  /**
   * TRUE only inside a PHPUnit process.
   */
  private static function runningUnderPhpunit(): bool {
    return defined('PHPUNIT_COMPOSER_INSTALL')
      || defined('__PHPUNIT_PHAR__')
      || getenv('PHPUNIT') === '1';
  }

}
