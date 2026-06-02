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
   * Tests that a webhook endpoint URL must be HTTPS.
   */
  public function testWebhookEndpointUrlMustBeHttps(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel');

    $this->submitForm([
      'webhooks[endpoints][0][id]' => 'ep1',
      'webhooks[endpoints][0][label]' => 'EP1',
      'webhooks[endpoints][0][url]' => 'http://example.com/hook',
      'webhooks[endpoints][0][enabled]' => 1,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('Endpoint 1 URL must use HTTPS.');
  }

  /**
   * Tests that two endpoints save to the webhook_endpoints sequence.
   */
  public function testMultipleEndpointsSave(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel');

    $this->submitForm([
      'webhooks[endpoints][0][id]' => 'ep1',
      'webhooks[endpoints][0][label]' => 'First',
      'webhooks[endpoints][0][url]' => 'https://one.example.com/hook',
      'webhooks[endpoints][0][enabled]' => 1,
      'webhooks[endpoints][1][id]' => 'ep2',
      'webhooks[endpoints][1][label]' => 'Second',
      'webhooks[endpoints][1][url]' => 'https://two.example.com/hook',
      'webhooks[endpoints][1][events]' => "mcp.entity.delete",
      'webhooks[endpoints][1][enabled]' => 0,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $endpoints = $this->config('mcp_sentinel.settings')->get('webhook_endpoints');
    $this->assertCount(2, $endpoints);
    $this->assertSame('ep1', $endpoints[0]['id']);
    $this->assertSame('https://one.example.com/hook', $endpoints[0]['url']);
    $this->assertTrue($endpoints[0]['enabled']);
    // Fix 5: allow_internal must default to FALSE when not checked.
    $this->assertFalse($endpoints[0]['allow_internal'],
      'allow_internal must default to FALSE.');
    $this->assertSame('ep2', $endpoints[1]['id']);
    $this->assertSame(['mcp.entity.delete'], $endpoints[1]['events']);
    $this->assertFalse($endpoints[1]['enabled']);
  }

  /**
   * Fix 5: per-endpoint allow_internal is saved when checked.
   */
  public function testPerEndpointAllowInternalSaves(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel');

    $this->submitForm([
      'webhooks[endpoints][0][id]'             => 'internal_ep',
      'webhooks[endpoints][0][label]'          => 'Internal VPN',
      'webhooks[endpoints][0][url]'            => 'https://internal.corp/hook',
      'webhooks[endpoints][0][enabled]'        => 1,
      'webhooks[endpoints][0][allow_internal]' => 1,
    ], 'Save configuration');

    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $endpoints = $this->config('mcp_sentinel.settings')->get('webhook_endpoints');
    $this->assertCount(1, $endpoints);
    $this->assertSame('internal_ep', $endpoints[0]['id']);
    $this->assertTrue($endpoints[0]['allow_internal'],
      'allow_internal must be TRUE when the checkbox is checked.');
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
