<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the MCP Sentinel hook_help() overview page.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpHelpTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel', 'help'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * The help page renders the module overview for an administrator.
   */
  public function testHelpPageRenders(): void {
    $admin = $this->drupalCreateUser([
      'access administration pages',
      'access help pages',
    ]);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/help/mcp_sentinel');
    $assert = $this->assertSession();
    $assert->statusCodeEquals(200);
    // Known phrases from mcp_sentinel_help().
    $assert->pageTextContains('governance layer');
    $assert->pageTextContains('Trust model');
    $assert->pageTextContains('Tamper-evident audit log');
    // The help page links to the settings and audit routes.
    $assert->linkByHrefExists('/admin/config/services/mcp-sentinel');
    $assert->linkByHrefExists('/admin/reports/mcp-sentinel/audit');
  }

}
