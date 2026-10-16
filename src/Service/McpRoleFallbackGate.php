<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Site\Settings;
use Symfony\Component\HttpFoundation\Request;

/**
 * Whether the local-dev role fallback may run for this process or request.
 *
 * The config checkbox governed_role_fallback is not enough. Production
 * enablement is $settings['mcp_sentinel_allow_role_fallback'] = TRUE in
 * settings.php; config import cannot set that key. PHPUnit and the
 * PHP built-in server (cli-server) are the kernel / functional test
 * permits. HTTP fallback is refused when reverse_proxy is on or when
 * any Forwarded or X-Forwarded-* header is present.
 */
final class McpRoleFallbackGate {

  /**
   * Settings.php key. Not a config object.
   */
  public const SETTINGS_KEY = 'mcp_sentinel_allow_role_fallback';

  /**
   * Settings.php principal used by PHPUnit's built-in server only.
   *
   * Functional tests cannot mint a Paladin bearer. The factory reads
   * this map only after readiness has taken the role-fallback path,
   * and only in PHPUnit or cli-server. Other SAPIs ignore it.
   */
  public const TEST_PRINCIPAL_KEY = 'mcp_sentinel_role_fallback_test_principal';

  /**
   * Whether role fallback may run for this request (or CLI with no request).
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The current HTTP request, or NULL on CLI.
   */
  public static function permitted(?Request $request): bool {
    if (self::looksProxied($request)) {
      return FALSE;
    }
    if (Settings::get(self::SETTINGS_KEY) === TRUE) {
      return TRUE;
    }
    return self::inPhpUnit() || self::inLocalDevSapi();
  }

  /**
   * TRUE when the HTTP hop looks proxied or reverse_proxy is enabled.
   *
   * CLI with no request is not proxied. reverse_proxy is checked only
   * when a request exists so a web-stack proxy setting does not block
   * a settings.php-enabled Drush fallback.
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The current HTTP request, or NULL on CLI.
   */
  public static function looksProxied(?Request $request): bool {
    if ($request === NULL) {
      return FALSE;
    }
    if (Settings::get('reverse_proxy')) {
      return TRUE;
    }
    if ($request->headers->has('forwarded')) {
      return TRUE;
    }
    foreach (array_keys($request->headers->all()) as $name) {
      if (str_starts_with(strtolower((string) $name), 'x-forwarded-')) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * TRUE when this process is PHPUnit.
   */
  public static function inPhpUnit(): bool {
    return defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_PHAR__');
  }

  /**
   * TRUE on the PHP built-in server used by Drupal functional tests.
   *
   * Production SAPIs (fpm-fcgi, apache2handler) are not permitted
   * here. Generic CLI / Drush still needs the settings.php flag.
   */
  public static function inLocalDevSapi(): bool {
    return PHP_SAPI === 'cli-server';
  }

}
