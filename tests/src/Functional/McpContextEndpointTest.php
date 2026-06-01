<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests the MCP Sentinel health and context endpoints.
 *
 * @group mcp_sentinel
 */
final class McpContextEndpointTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests the unauthenticated health endpoint.
   */
  public function testHealthEndpoint(): void {
    $this->drupalGet('/drupal-mcp/health');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->responseContains('"status":"ok"');

    $this->config('mcp_sentinel.settings')->set('enabled', FALSE)->save();
    $this->drupalGet('/drupal-mcp/health');
    $this->assertSession()->statusCodeEquals(503);
    $this->assertSession()->responseContains('"status":"disabled"');
  }

  /**
   * Tests that the context endpoint is protected.
   */
  public function testContextEndpointRequiresPermission(): void {
    // Anonymous users lack 'access mcp sentinel context'.
    $this->drupalGet('/drupal-mcp/context');
    $this->assertSession()->statusCodeEquals(403);
  }

}
