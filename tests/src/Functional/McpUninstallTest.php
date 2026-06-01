<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests that uninstall cleans up everything the module created.
 *
 * @group mcp_sentinel
 */
final class McpUninstallTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Uninstalling the module removes the mcp_api role it created on install.
   */
  public function testUninstallRemovesMcpApiRole(): void {
    $storage = $this->container->get('entity_type.manager')->getStorage('user_role');
    $this->assertNotNull($storage->load('mcp_api'), 'mcp_api role exists after install.');

    $this->container->get('module_installer')->uninstall(['mcp_sentinel']);

    $storage = $this->container->get('entity_type.manager')->getStorage('user_role');
    $this->assertNull($storage->load('mcp_api'), 'mcp_api role removed after uninstall.');
  }

}
