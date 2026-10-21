<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_auth;

use Drupal\Core\DestructableInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;

/**
 * Decorates @module_handler and lies about mcp_sentinel_test's path.
 *
 * The decorator is the live handler. Ownership that asks it
 * will treat the rogue class as test-module-owned.
 */
final class LyingTestModulePathHandler implements ModuleHandlerInterface {

  use FakeTestModuleExtensionTrait;

  /**
   * Constructs the decorator.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $inner
   *   The decorated handler.
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
    return $this->inner->moduleExists($module);
  }

  /**
   * {@inheritdoc}
   */
  public function getModule($name) {
    if ($name === 'mcp_sentinel_test') {
      return $this->fakeTestModule();
    }
    return $this->inner->getModule($name);
  }

  /**
   * {@inheritdoc}
   */
  public function getModuleList() {
    $list = $this->inner->getModuleList();
    if (isset($list['mcp_sentinel_test'])) {
      $list['mcp_sentinel_test'] = $this->fakeTestModule();
    }
    return $list;
  }

  /**
   * Drupal 10 ModuleHandlerInterface extends DestructableInterface.
   */
  public function destruct(): void {
    if ($this->inner instanceof DestructableInterface) {
      $this->inner->destruct();
    }
  }

  /**
   * {@inheritdoc}
   */
  public function load($name) {
    return $this->inner->load($name);
  }

  /**
   * {@inheritdoc}
   */
  public function loadAll(): void {
    $this->inner->loadAll();
  }

  /**
   * {@inheritdoc}
   */
  public function isLoaded() {
    return $this->inner->isLoaded();
  }

  /**
   * {@inheritdoc}
   */
  public function reload(): void {
    $this->inner->reload();
  }

  /**
   * {@inheritdoc}
   */
  public function setModuleList(array $module_list = []): void {
    $this->inner->setModuleList($module_list);
  }

  /**
   * {@inheritdoc}
   */
  public function addModule($name, $path): void {
    $this->inner->addModule($name, $path);
  }

  /**
   * {@inheritdoc}
   */
  public function addProfile($name, $path): void {
    $this->inner->addProfile($name, $path);
  }

  /**
   * {@inheritdoc}
   */
  public function buildModuleDependencies(array $modules) {
    return $this->inner->buildModuleDependencies($modules);
  }

  /**
   * {@inheritdoc}
   */
  public function loadAllIncludes($type, $name = NULL): void {
    $this->inner->loadAllIncludes($type, $name);
  }

  /**
   * {@inheritdoc}
   */
  public function loadInclude($module, $type, $name = NULL) {
    return $this->inner->loadInclude($module, $type, $name);
  }

  /**
   * {@inheritdoc}
   */
  public function getHookInfo() {
    return $this->inner->getHookInfo();
  }

  /**
   * {@inheritdoc}
   */
  public function writeCache(): void {
    $this->inner->writeCache();
  }

  /**
   * {@inheritdoc}
   */
  public function resetImplementations(): void {
    $this->inner->resetImplementations();
  }

  /**
   * {@inheritdoc}
   */
  public function hasImplementations(string $hook, $modules = NULL): bool {
    return $this->inner->hasImplementations($hook, $modules);
  }

  /**
   * {@inheritdoc}
   */
  public function invokeAllWith(string $hook, callable $callback): void {
    $this->inner->invokeAllWith($hook, $callback);
  }

  /**
   * {@inheritdoc}
   */
  public function invoke($module, $hook, array $args = []) {
    return $this->inner->invoke($module, $hook, $args);
  }

  /**
   * {@inheritdoc}
   */
  public function invokeAll($hook, array $args = []) {
    return $this->inner->invokeAll($hook, $args);
  }

  /**
   * {@inheritdoc}
   */
  public function invokeDeprecated($description, $module, $hook, array $args = []) {
    return $this->inner->invokeDeprecated($description, $module, $hook, $args);
  }

  /**
   * {@inheritdoc}
   */
  public function invokeAllDeprecated($description, $hook, array $args = []) {
    return $this->inner->invokeAllDeprecated($description, $hook, $args);
  }

  /**
   * {@inheritdoc}
   */
  public function alter($type, &$data, &$context1 = NULL, &$context2 = NULL): void {
    $this->inner->alter($type, $data, $context1, $context2);
  }

  /**
   * {@inheritdoc}
   */
  public function alterDeprecated($description, $type, &$data, &$context1 = NULL, &$context2 = NULL): void {
    $this->inner->alterDeprecated($description, $type, $data, $context1, $context2);
  }

  /**
   * {@inheritdoc}
   */
  public function getModuleDirectories() {
    return $this->inner->getModuleDirectories();
  }

  /**
   * {@inheritdoc}
   */
  public function getName($module) {
    return $this->inner->getName($module);
  }

}
