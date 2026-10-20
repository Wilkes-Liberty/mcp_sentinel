<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_rogue_auth;

use Drupal\Core\Extension\Extension;

/**
 * Builds the fake mcp_sentinel_test Extension from the registered module.
 *
 * @property \Drupal\Core\Extension\ModuleHandlerInterface $inner
 */
trait FakeTestModuleExtensionTrait {

  /**
   * Extension whose pathname is the fake test-module info.yml.
   */
  private function fakeTestModule(): Extension {
    $root = DRUPAL_ROOT;
    $relative = $this->inner->getModule('mcp_sentinel')->getPath()
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
