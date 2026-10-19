<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Site\Settings;

/**
 * Whether a principal-auth hook is owned by mcp_sentinel_test.
 *
 * Ownership is the test module's real path (or the provider
 * discovered from that path), not a class-namespace prefix.
 * Production stays closed unless the test gate is set.
 */
final class McpPrincipalAuthExtensionOwnership {

  /**
   * Only implementation that may be admitted.
   */
  public const TEST_MODULE = 'mcp_sentinel_test';

  /**
   * Legacy hook id. Always dropped.
   */
  public const LEGACY_ID = 'mcp_sentinel.principal_auth_extension';

  /**
   * Namespaced hook id.
   */
  public const SERVICE_ID = 'mcp_sentinel_test.principal_auth_extension';

  /**
   * Audit-chain operation for a rejected hook.
   */
  public const AUDIT_OPERATION = 'principal_auth_extension_rejected';

  /**
   * Container parameter listing compile-time rejections.
   */
  public const REJECTED_PARAMETER = 'mcp_sentinel.rejected_principal_auth_extensions';

  /**
   * TRUE when this object may be consulted.
   *
   * Fail closed: a missing test module, a closed test gate,
   * or a class file outside the test module's path is denied.
   *
   * @param object $extension
   *   Candidate hook.
   * @param array<string, mixed>|null $modules
   *   container.modules, or NULL to read the live module list.
   *
   * @return bool
   *   TRUE when the hook may be consulted.
   */
  public static function isAdmitted(
    object $extension,
    ?array $modules = NULL,
  ): bool {
    if (!$extension instanceof McpPrincipalAuthExtensionInterface) {
      return FALSE;
    }
    if (!self::testGateOpen()) {
      return FALSE;
    }
    return self::isOwnedByTestModule($extension, $modules);
  }

  /**
   * TRUE when PHPUnit is running or the settings.php test gate is set.
   *
   * Kernel and unit tests use PHPUnit. Functional tests write
   * mcp_sentinel_allow_role_fallback in settings.php. Production
   * has neither unless an operator sets that flag.
   *
   * @return bool
   *   TRUE when the test gate is open.
   */
  public static function testGateOpen(): bool {
    if (McpRoleFallbackGate::inPhpUnit()) {
      return TRUE;
    }
    try {
      return Settings::get(McpRoleFallbackGate::SETTINGS_KEY) === TRUE;
    }
    catch (\Throwable) {
      return FALSE;
    }
  }

  /**
   * TRUE when the class file lives under mcp_sentinel_test.
   *
   * @param object $extension
   *   Candidate hook.
   * @param array<string, mixed>|null $modules
   *   container.modules, or NULL to read the live module list.
   *
   * @return bool
   *   TRUE when the class file is under mcp_sentinel_test.
   */
  public static function isOwnedByTestModule(
    object $extension,
    ?array $modules = NULL,
  ): bool {
    $file = self::realClassFile($extension::class);
    if ($file === NULL) {
      return FALSE;
    }
    $moduleDir = self::testModuleDirectory($modules);
    if ($moduleDir === NULL) {
      return FALSE;
    }
    return str_starts_with($file, $moduleDir . DIRECTORY_SEPARATOR);
  }

  /**
   * TRUE when $class is owned by mcp_sentinel_test.
   *
   * @param string $class
   *   FQCN.
   * @param array<string, mixed> $modules
   *   container.modules.
   *
   * @return bool
   *   TRUE when $class is owned by mcp_sentinel_test.
   */
  public static function classIsOwned(string $class, array $modules): bool {
    if ($class === '' || !class_exists($class)) {
      return FALSE;
    }
    $file = self::realClassFile($class);
    if ($file === NULL) {
      return FALSE;
    }
    $moduleDir = self::testModuleDirectory($modules);
    if ($moduleDir === NULL) {
      return FALSE;
    }
    return str_starts_with($file, $moduleDir . DIRECTORY_SEPARATOR);
  }

  /**
   * Module that defines $class, from the real path.
   *
   * @param string $class
   *   FQCN.
   * @param array<string, mixed> $modules
   *   container.modules or the live module list as pathnames.
   *
   * @return string
   *   Module machine name, or empty when unknown.
   */
  public static function providerOfClass(string $class, array $modules): string {
    $file = self::realClassFile($class);
    if ($file === NULL) {
      return '';
    }
    foreach ($modules as $name => $info) {
      if (!is_string($name) || $name === '' || !is_array($info)) {
        continue;
      }
      $pathname = $info['pathname'] ?? '';
      if (!is_string($pathname) || $pathname === '') {
        continue;
      }
      $dir = realpath(dirname($pathname));
      if ($dir === FALSE) {
        continue;
      }
      if (str_starts_with($file, $dir . DIRECTORY_SEPARATOR)) {
        return $name;
      }
    }
    return '';
  }

  /**
   * Module that shipped this object, from the live module list.
   *
   * @param object $extension
   *   Candidate hook.
   *
   * @return string
   *   Module machine name, or empty when unknown.
   */
  public static function providerOf(object $extension): string {
    $modules = self::liveModulePathnames();
    if ($modules === []) {
      $modules = self::shippedTestModuleAsList();
    }
    return self::providerOfClass($extension::class, $modules);
  }

  /**
   * Service id currently holding this object, if any.
   *
   * @param object $extension
   *   Candidate hook.
   *
   * @return string
   *   Service id, or the namespaced hook id when unknown.
   */
  public static function serviceIdOf(object $extension): string {
    if (!class_exists(\Drupal::class)
      || !\Drupal::hasContainer()) {
      return self::SERVICE_ID;
    }
    $container = \Drupal::getContainer();
    foreach ($container->getServiceIds() as $id) {
      if (!$container->initialized($id)) {
        continue;
      }
      try {
        if ($container->get($id) === $extension) {
          return $id;
        }
      }
      catch (\Throwable) {
        continue;
      }
    }
    return self::SERVICE_ID;
  }

  /**
   * Writes one governance row naming the service and provider.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger|null $auditLogger
   *   Chain writer. NULL skips the write; the hook is still ignored.
   * @param string $serviceId
   *   Offending service id.
   * @param string $provider
   *   Defining module, or empty when unknown.
   */
  public static function recordRejection(
    ?McpAuditLogger $auditLogger,
    string $serviceId,
    string $provider,
  ): void {
    if ($auditLogger === NULL) {
      return;
    }
    try {
      $auditLogger->logAlways(self::AUDIT_OPERATION, [
        'service' => $serviceId,
        'provider' => $provider,
      ]);
    }
    catch (\Throwable) {
      // Fail closed: the hook stays ignored even if the row
      // cannot be written.
    }
  }

  /**
   * Absolute directory of the enabled mcp_sentinel_test module.
   *
   * @param array<string, mixed>|null $modules
   *   container.modules, or NULL to read the live list.
   *
   * @return string|null
   *   Absolute module directory, or NULL when it cannot be proven.
   */
  public static function testModuleDirectory(?array $modules = NULL): ?string {
    if (is_array($modules)) {
      return self::directoryFromModuleList($modules);
    }
    $live = self::liveModulePathnames();
    if ($live !== []) {
      return self::directoryFromModuleList($live);
    }
    return self::shippedTestModuleDirectory();
  }

  /**
   * Realpath of the class file, or NULL when it cannot be proven.
   *
   * @param string $class
   *   FQCN.
   *
   * @return string|null
   *   Absolute class file, or NULL.
   */
  private static function realClassFile(string $class): ?string {
    if ($class === '' || !class_exists($class)) {
      return NULL;
    }
    try {
      $file = (new \ReflectionClass($class))->getFileName();
    }
    catch (\ReflectionException) {
      return NULL;
    }
    if (!is_string($file) || $file === '') {
      return NULL;
    }
    $real = realpath($file);
    return $real === FALSE ? NULL : $real;
  }

  /**
   * Directory from container.modules for mcp_sentinel_test.
   *
   * The pathname must be the module's own info.yml. A forged
   * pathname whose basename is not mcp_sentinel_test.info.yml
   * is ignored.
   *
   * @param array<string, mixed> $modules
   *   container.modules.
   *
   * @return string|null
   *   Absolute module directory, or NULL.
   */
  private static function directoryFromModuleList(array $modules): ?string {
    if (!isset($modules[self::TEST_MODULE])
      || !is_array($modules[self::TEST_MODULE])) {
      return NULL;
    }
    $pathname = $modules[self::TEST_MODULE]['pathname'] ?? '';
    if (!is_string($pathname) || $pathname === '') {
      return NULL;
    }
    $realInfo = realpath($pathname);
    if ($realInfo === FALSE
      || basename($realInfo) !== self::TEST_MODULE . '.info.yml') {
      return NULL;
    }
    return dirname($realInfo);
  }

  /**
   * Live enabled-module pathnames, keyed by machine name.
   *
   * @return array<string, array{pathname: string}>
   *   Pathnames from the extension list.
   */
  private static function liveModulePathnames(): array {
    if (!class_exists(\Drupal::class)
      || !\Drupal::hasService('module_handler')) {
      return [];
    }
    $handler = \Drupal::service('module_handler');
    if (!$handler instanceof ModuleHandlerInterface
      || !$handler->moduleExists(self::TEST_MODULE)) {
      return [];
    }
    $list = [];
    foreach ($handler->getModuleList() as $name => $extension) {
      $pathname = $extension->getPathname();
      if (!is_string($pathname) || $pathname === '') {
        continue;
      }
      if (!str_starts_with($pathname, '/')
        && defined('DRUPAL_ROOT')) {
        $pathname = DRUPAL_ROOT . '/' . $pathname;
      }
      $list[$name] = ['pathname' => $pathname];
    }
    return $list;
  }

  /**
   * Directory of the autoloaded test-module implementation.
   *
   * Used only when the extension list is unavailable (unit
   * tests). Kernel and production use the module handler.
   *
   * @return string|null
   *   Absolute module directory, or NULL.
   */
  private static function shippedTestModuleDirectory(): ?string {
    $class = 'Drupal\\mcp_sentinel_test\\Service\\McpTestPrincipalAuthExtension';
    if (!class_exists($class)) {
      return NULL;
    }
    $file = self::realClassFile($class);
    if ($file === NULL) {
      return NULL;
    }
    return dirname($file, 3);
  }

  /**
   * One-entry module list from the shipped test implementation.
   *
   * @return array<string, array{pathname: string}>
   *   Synthetic container.modules row.
   */
  private static function shippedTestModuleAsList(): array {
    $dir = self::shippedTestModuleDirectory();
    if ($dir === NULL) {
      return [];
    }
    $info = $dir . DIRECTORY_SEPARATOR . self::TEST_MODULE . '.info.yml';
    if (!is_file($info)) {
      return [];
    }
    return [
      self::TEST_MODULE => ['pathname' => $info],
    ];
  }

}
