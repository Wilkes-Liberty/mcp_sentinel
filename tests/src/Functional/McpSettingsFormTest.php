<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests the MCP Sentinel settings form.
 *
 * @group mcp_sentinel
 */
final class McpSettingsFormTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * @covers \Drupal\mcp_sentinel\Form\McpSettingsForm
   */
  public function testSettingsFormSavesConfig(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->fieldExists('enabled');

    $this->submitForm([
      'enabled' => 1,
      'governed_roles[mcp_api]' => 'mcp_api',
      'audit_enabled' => 1,
      'audit_retention_days' => 30,
    ], 'Save configuration');

    $config = $this->config('mcp_sentinel.settings');
    $this->assertTrue($config->get('enabled'));
    $this->assertContains('mcp_api', $config->get('governed_roles'));
    $this->assertSame(30, $config->get('audit_retention_days'));
  }

  /**
   * Tests that webhook URLs must be HTTPS.
   */
  public function testWebhookUrlMustBeHttps(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel');

    $this->submitForm([
      'webhook_enabled' => TRUE,
      'webhook_url' => 'http://example.com/hook',
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Webhook URL must use HTTPS.');
  }

  /**
   * Tests that the form requires the admin permission.
   */
  public function testFormRequiresPermission(): void {
    $this->drupalLogin($this->drupalCreateUser([]));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(403);
  }

}
