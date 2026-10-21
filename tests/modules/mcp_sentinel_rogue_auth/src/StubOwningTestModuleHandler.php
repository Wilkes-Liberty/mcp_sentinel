<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_auth;

use Drupal\Core\Extension\ModuleHandlerInterface;

/**
 * Reports mcp_sentinel_test at the rogue class directory.
 *
 * Attack fixture for a rewired factory/subscriber handler.
 */
final class StubOwningTestModuleHandler implements ModuleHandlerInterface {

  use FakeTestModuleExtensionTrait;

  /**
   * Constructs the stub.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $inner
   *   The live handler. The stub is not a decorator; this is
   *   only used to read the registered mcp_sentinel path.
   */
  public function __construct(
    private readonly ModuleHandlerInterface $inner,
  ) {
    $this->ensureFakeTestModuleInfo();
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

}
