<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_auth;

use Drupal\Core\Extension\Extension;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;

/**
 * Reports mcp_sentinel_test at the rogue class directory.
 *
 * Attack fixture for a rewired factory/subscriber handler.
 */
final class StubOwningTestModuleHandler implements ModuleHandlerInterface {

  /**
   * Absolute path of the fake mcp_sentinel_test.info.yml.
   */
  private readonly string $infoPathname;

  /**
   * Constructs the stub.
   *
   * Writes the fake info.yml at runtime so phpunit's extension
   * scan (which keys modules by info.yml basename) does not
   * steal the mcp_sentinel_test namespace.
   */
  public function __construct() {
    $file = (new \ReflectionClass(McpRoguePrincipalAuthExtension::class))->getFileName();
    $this->infoPathname = dirname((string) $file) . '/mcp_sentinel_test.info.yml';
    if (!is_file($this->infoPathname)) {
      file_put_contents(
        $this->infoPathname,
        "name: 'MCP Sentinel stub-handler fake'\ntype: module\nhidden: true\n",
      );
    }
    register_shutdown_function(static function (string $path): void {
      if (is_file($path)) {
        unlink($path);
      }
    }, $this->infoPathname);
  }

  /**
   * {@inheritdoc}
   */
  public function moduleExists($module) {
    return $module === 'mcp_sentinel_test';
  }

  /**
   * {@inheritdoc}
   */
  public function getModule($name) {
    return $this->fakeTestModule();
  }

  /**
   * {@inheritdoc}
   */
  public function getModuleList() {
    return ['mcp_sentinel_test' => $this->fakeTestModule()];
  }

  /**
   * Drupal 10 ModuleHandlerInterface extends DestructableInterface.
   */
  public function destruct(): void {}

  /**
   * {@inheritdoc}
   */
  public function load($name) {
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function loadAll(): void {}

  /**
   * {@inheritdoc}
   */
  public function isLoaded() {
    return TRUE;
  }

  /**
   * {@inheritdoc}
   */
  public function reload(): void {}

  /**
   * {@inheritdoc}
   */
  public function setModuleList(array $module_list = []): void {}

  /**
   * {@inheritdoc}
   */
  public function addModule($name, $path): void {}

  /**
   * {@inheritdoc}
   */
  public function addProfile($name, $path): void {}

  /**
   * {@inheritdoc}
   */
  public function buildModuleDependencies(array $modules) {
    return $modules;
  }

  /**
   * {@inheritdoc}
   */
  public function loadAllIncludes($type, $name = NULL): void {}

  /**
   * {@inheritdoc}
   */
  public function loadInclude($module, $type, $name = NULL) {
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function getHookInfo() {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function writeCache(): void {}

  /**
   * {@inheritdoc}
   */
  public function resetImplementations(): void {}

  /**
   * {@inheritdoc}
   */
  public function hasImplementations(string $hook, $modules = NULL): bool {
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function invokeAllWith(string $hook, callable $callback): void {}

  /**
   * {@inheritdoc}
   */
  public function invoke($module, $hook, array $args = []) {
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function invokeAll($hook, array $args = []) {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function invokeDeprecated($description, $module, $hook, array $args = []) {
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function invokeAllDeprecated($description, $hook, array $args = []) {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function alter($type, &$data, &$context1 = NULL, &$context2 = NULL): void {}

  /**
   * {@inheritdoc}
   */
  public function alterDeprecated($description, $type, &$data, &$context1 = NULL, &$context2 = NULL): void {}

  /**
   * {@inheritdoc}
   */
  public function getModuleDirectories() {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function getName($module) {
    return $module;
  }

  /**
   * Extension whose pathname is the fake test-module info.yml.
   */
  private function fakeTestModule(): Extension {
    $root = defined('DRUPAL_ROOT') ? (string) DRUPAL_ROOT : '';
    $pathname = $this->infoPathname;
    if ($root !== '' && str_starts_with($pathname, $root . '/')) {
      $pathname = substr($pathname, strlen($root) + 1);
    }
    return new Extension($root !== '' ? $root : dirname($this->infoPathname, 6), 'module', $pathname);
  }

}
