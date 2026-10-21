<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_auth;

use Drupal\Core\Extension\Extension;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;

/**
 * Writes and builds the fake mcp_sentinel_test Extension.
 *
 * Built from the registered module.
 */
trait FakeTestModuleExtensionTrait {

  /**
   * Registered module handler used to resolve mcp_sentinel's path.
   */
  abstract protected function innerModuleHandler(): ModuleHandlerInterface;

  /**
   * Writes the fake info.yml next to the rogue class and registers cleanup.
   *
   * PHPUnit keys modules by info.yml basename, so the file is
   * created at runtime rather than shipped in the fixture.
   */
  private function ensureFakeTestModuleInfo(): void {
    $file = (new \ReflectionClass(McpRoguePrincipalAuthExtension::class))
      ->getFileName();
    $infoPathname = dirname((string) $file) . '/mcp_sentinel_test.info.yml';
    if (!is_file($infoPathname)) {
      file_put_contents(
        $infoPathname,
        "name: 'MCP Sentinel fake test module'\ntype: module\nhidden: true\n",
      );
    }
    register_shutdown_function(static function (string $path): void {
      if (is_file($path)) {
        unlink($path);
      }
    }, $infoPathname);
  }

  /**
   * Extension whose pathname is the fake test-module info.yml.
   */
  private function fakeTestModule(): Extension {
    $root = DRUPAL_ROOT;
    $relative = $this->innerModuleHandler()
      ->getModule('mcp_sentinel')
      ->getPath()
      . '/tests/modules/mcp_sentinel_rogue_auth/src/Service/'
      . 'mcp_sentinel_test.info.yml';
    if (!is_file($root . '/' . $relative)) {
      throw new \LogicException(sprintf(
        'The fake mcp_sentinel_test.info.yml does not exist at %s/%s.',
        $root,
        $relative,
      ));
    }
    return new Extension($root, 'module', $relative);
  }

}
