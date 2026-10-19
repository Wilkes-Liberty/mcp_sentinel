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
 * settings.php; config import cannot set that key. That flag is for
 * local-only stacks: header-based proxy detection misses a proxy that
 * adds no Forwarded or X-Forwarded-* headers. PHPUnit is the kernel /
 * unit-test permit. Functional tests write the settings.php flag.
 * HTTP fallback is refused when reverse_proxy is on or when any
 * Forwarded or X-Forwarded-* header is present. cli-server is not a
 * permit. A Drupal test child (DRUPAL_TEST_IN_CHILD_SITE) on any
 * SAPI — Apache on drupal.org CI, or the PHP built-in server —
 * may use the settings.php test principal after readiness stamps
 * role fallback. Production SAPIs without that constant ignore it.
 */
final class McpRoleFallbackGate {

  /**
   * Settings.php key. Not a config object.
   */
  public const SETTINGS_KEY = 'mcp_sentinel_allow_role_fallback';

  /**
   * Settings.php principal used by PHPUnit and Drupal test children.
   *
   * Functional tests cannot mint a Paladin bearer. The factory reads
   * this map only after readiness has taken the role-fallback path,
   * and only in PHPUnit or a Drupal test child site
   * (DRUPAL_TEST_IN_CHILD_SITE). Production SAPIs ignore it.
   */
  public const TEST_PRINCIPAL_KEY = 'mcp_sentinel_role_fallback_test_principal';

  /**
   * Whether role fallback may run for this request (or CLI with no request).
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The current HTTP request, or NULL on CLI.
   * @param \Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment|null $environment
   *   Process probe. NULL reads the live process. Tests inject a
   *   production SAPI so the settings.php requirement is not hidden
   *   by PHPUnit.
   */
  public static function permitted(
    ?Request $request,
    ?McpRoleFallbackEnvironment $environment = NULL,
  ): bool {
    $environment ??= McpRoleFallbackEnvironment::detect();
    if (self::looksProxied($request)) {
      return FALSE;
    }
    if (Settings::get(self::SETTINGS_KEY) === TRUE) {
      return TRUE;
    }
    return $environment->inPhpUnit();
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
    return McpRoleFallbackEnvironment::detect()->inPhpUnit();
  }

  /**
   * TRUE on any SAPI that is a Drupal functional-test child site.
   *
   * DRUPAL_TEST_IN_CHILD_SITE is written only into the isolated
   * simpletest settings.php. Production Apache, FPM, and cli-server
   * do not define it. Used for the test-principal map and the
   * deferred claimless seal. Production php -S / drush runserver /
   * a PaaS image is not a permit.
   *
   * @param \Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment|null $environment
   *   Process probe. NULL reads the live process.
   */
  public static function inTestChildSite(
    ?McpRoleFallbackEnvironment $environment = NULL,
  ): bool {
    $environment ??= McpRoleFallbackEnvironment::detect();
    return $environment->inDrupalTestChildSite();
  }

  /**
   * TRUE on the PHP built-in server for a Drupal functional-test child.
   *
   * Prefer inTestChildSite() for new callers. drupal.org GitLab CI
   * serves functional tests from Apache, not cli-server.
   *
   * @param \Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment|null $environment
   *   Process probe. NULL reads the live process.
   */
  public static function inTestChildServer(
    ?McpRoleFallbackEnvironment $environment = NULL,
  ): bool {
    $environment ??= McpRoleFallbackEnvironment::detect();
    return $environment->sapi() === 'cli-server'
      && $environment->inDrupalTestChildSite();
  }

}
