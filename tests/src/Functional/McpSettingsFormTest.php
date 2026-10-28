<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\key\Entity\Key;
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
   * The settings page cross-links to the dashboard, gated on view access.
   *
   * @covers \Drupal\mcp_sentinel\Form\McpSettingsForm
   */
  public function testOperationalCrossLinks(): void {
    // A user who can view the operational reports sees the cross-links.
    $viewer = $this->drupalCreateUser([
      'administer mcp sentinel',
      'view mcp sentinel audit log',
    ]);
    $this->drupalLogin($viewer);
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->linkExists('Governance dashboard');
    $this->assertSession()->linkByHrefExists('/admin/reports/mcp-sentinel');
    $this->assertSession()->linkByHrefExists('/admin/reports/mcp-sentinel/audit');

    // A config-only admin without report access does not see a link they
    // could not use.
    $configOnly = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($configOnly);
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->linkNotExists('Governance dashboard');
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

  /**
   * The settings page renders vertical tabs and round-trips config unchanged.
   */
  public function testVerticalTabsRenderAndConfigRoundTrips(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(200);
    // Vertical-tabs wrapper present (server-side rendered class; JS adds
    // .vertical-tabs but functional tests run without JavaScript).
    $this->assertSession()->elementExists('css', '[data-vertical-tabs-panes]');
    // Each group is now a details element (vertical_tabs converts fieldsets).
    $this->assertSession()->pageTextContains('MCP Access');
    $this->assertSession()->pageTextContains('OAuth agent channel');
    $this->assertSession()->pageTextContains('Audit Logging');
    // The event-filter field names the three events that actually enqueue.
    $this->assertSession()->pageTextContains('mcp.entity.presave');
    $this->assertSession()->pageTextContains('mcp.entity.delete');
    $this->assertSession()->pageTextContains('mcp.anomaly.alert');
    $this->assertSession()->pageTextContains('entity write, before commit');
    // Operator broadcast field exists.
    $this->assertSession()->fieldExists('dashboard_broadcast_message');
    // Save with no edits; assert the stored list shapes are byte-identical.
    $before = \Drupal::config('mcp_sentinel.settings')->getRawData();
    $this->submitForm([], 'Save configuration');
    $after = \Drupal::config('mcp_sentinel.settings')->getRawData();
    $this->assertSame($before['dlp_patterns'], $after['dlp_patterns']);
    $this->assertSame($before['anomaly_rules'], $after['anomaly_rules']);
    $this->assertSame($before['webhook_endpoints'], $after['webhook_endpoints']);
  }

  /**
   * Stored endpoints render as rows and round-trip byte-identically.
   */
  public function testEndpointEditorRoundTripsStoredEndpoints(): void {
    $key = Key::create([
      'id' => 'wh_key',
      'label' => 'WH',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 's3cret'],
    ]);
    $key->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => 'wh_key',
        'events' => ['mcp.entity.presave'],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->fieldValueEquals('webhooks[endpoints][0][id]', 'siem');
    $this->submitForm([], 'Save configuration');
    $this->assertSame([[
      'id' => 'siem',
      'label' => 'SIEM',
      'url' => 'https://siem.example.com/hook',
      'secret_key' => 'wh_key',
      'events' => ['mcp.entity.presave'],
      'enabled' => TRUE,
      'allow_internal' => FALSE,
    ],
    ], \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints'));
  }

  /**
   * Leftover webhook keys are gone after 10022 and stay gone on save.
   *
   * The form no longer ships webhooks_legacy or the global
   * allow_internal_webhook_urls checkbox, and submit no longer set()s those
   * keys. After 10022 clears existing-site leftovers, a settings save must
   * not recreate them.
   */
  public function testLeftoverWebhookKeysGoneAfterSettingsSave(): void {
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.settings') ?: [];
    $data['webhook_enabled'] = TRUE;
    $data['webhook_url'] = 'https://legacy.example/hook';
    $data['webhook_secret'] = 'stale';
    $data['webhook_secret_key'] = '';
    $data['allow_internal_webhook_urls'] = TRUE;
    $data['webhook_endpoints'] = [
      [
        'id' => 'default',
        'label' => 'Default',
        'url' => 'https://legacy.example/hook',
        'secret_key' => '',
        'events' => [],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
    ];
    $storage->write('mcp_sentinel.settings', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');

    require_once $this->root . '/' . $this->container->get('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';
    mcp_sentinel_update_10022();
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');

    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->fieldNotExists('webhooks_legacy[webhook_enabled]');
    $this->assertSession()->fieldNotExists('webhooks_legacy[webhook_url]');
    $this->assertSession()->fieldNotExists('webhooks_legacy[webhook_secret_key]');
    $this->assertSession()->fieldNotExists('webhooks[allow_internal_webhook_urls]');

    $this->submitForm([], 'Save configuration');
    $this->assertSession()->pageTextContains('The configuration options have been saved.');

    $config = \Drupal::config('mcp_sentinel.settings');
    $this->assertNull($config->get('webhook_enabled'),
      'webhook_enabled leftover must stay gone after a settings save.');
    $this->assertNull($config->get('webhook_url'),
      'webhook_url leftover must stay gone after a settings save.');
    $this->assertNull($config->get('webhook_secret'),
      'webhook_secret leftover must stay gone after a settings save.');
    $this->assertNull($config->get('webhook_secret_key'),
      'webhook_secret_key leftover must stay gone after a settings save.');
    $this->assertNull($config->get('allow_internal_webhook_urls'),
      'allow_internal_webhook_urls leftover must stay gone after a settings save.');
  }

  /**
   * Adding and removing endpoint rows mutates the stored sequence in shape.
   */
  public function testEndpointEditorAddAndRemoveRows(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => '',
        'events' => ['mcp.entity.presave'],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    // One stored endpoint + one blank trailing slot. Fill the blank slot, add a
    // new one via AJAX, then save.
    $this->submitForm([
      'webhooks[endpoints][1][id]' => 'soc',
      'webhooks[endpoints][1][label]' => 'SOC',
      'webhooks[endpoints][1][url]' => 'https://soc.example.com/hook',
      'webhooks[endpoints][1][events]' => 'mcp.entity.delete',
      'webhooks[endpoints][1][enabled]' => 1,
    ], 'Add endpoint');
    $this->submitForm([], 'Save configuration');
    $endpoints = \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints');
    $this->assertSame([
      [
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => '',
        'events' => ['mcp.entity.presave'],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      [
        'id' => 'soc',
        'label' => 'SOC',
        'url' => 'https://soc.example.com/hook',
        'secret_key' => '',
        'events' => ['mcp.entity.delete'],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
    ], $endpoints);

    // Remove the first endpoint via its own button; only "soc" remains.
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([], 'Remove endpoint 1');
    $this->submitForm([], 'Save configuration');
    $this->assertSame([[
      'id' => 'soc',
      'label' => 'SOC',
      'url' => 'https://soc.example.com/hook',
      'secret_key' => '',
      'events' => ['mcp.entity.delete'],
      'enabled' => TRUE,
      'allow_internal' => FALSE,
    ],
    ], \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints'));
  }

  /**
   * A stored mcp.entity.save filter is shown as stored.
   *
   * Rewriting the textarea would persist on any later save and start
   * entity-write deliveries nobody chose.
   */
  public function testRetiredSaveEventNameDisplayedAsStored(): void {
    $this->seedRetiredSaveWebhookEndpoint();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->fieldValueEquals(
      'webhooks[endpoints][0][events]',
      'mcp.entity.save',
    );
  }

  /**
   * An unrelated settings save must not rewrite a retired event filter.
   *
   * Changing the broadcast message is enough: if the form maps
   * mcp.entity.save to mcp.entity.presave, this assertion fails.
   */
  public function testUnrelatedSaveDoesNotRewriteRetiredWebhookEvent(): void {
    $this->seedRetiredSaveWebhookEndpoint();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'dashboard_broadcast_message' => 'Unrelated operator note',
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('Endpoint siem still filters on mcp.entity.save');
    $this->assertSession()->pageTextContains('Type mcp.entity.presave');
    $this->assertSame(
      ['mcp.entity.save'],
      \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints')[0]['events'],
    );
    $this->assertSame(
      '',
      (string) (\Drupal::config('mcp_sentinel.settings')->get('dashboard_broadcast')['message'] ?? ''),
    );
  }

  /**
   * Typing the live name persists the filter and writes an audit row.
   */
  public function testTypingLiveWebhookEventNameIsAudited(): void {
    $this->seedRetiredSaveWebhookEndpoint();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'webhooks[endpoints][0][events]' => 'mcp.entity.presave',
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertSame(
      ['mcp.entity.presave'],
      \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints')[0]['events'],
    );

    $meta = $this->latestWebhookEventFilterAudit();
    $this->assertSame('siem', $meta['endpoint_id']);
    $this->assertSame('changed', $meta['change']);
    $this->assertSame(['mcp.entity.save'], $meta['from']);
    $this->assertSame(['mcp.entity.presave'], $meta['to']);
  }

  /**
   * A stored or typed mcp.entity.save filter blocks the settings save.
   */
  public function testRetiredSaveEventNameRejectedOnSettingsSave(): void {
    $this->seedRetiredSaveWebhookEndpoint();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'webhooks[endpoints][0][events]' => 'mcp.entity.save',
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('Endpoint siem still filters on mcp.entity.save');
    $this->assertSession()->pageTextContains('Type mcp.entity.presave');
    $this->assertSame(
      ['mcp.entity.save'],
      \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints')[0]['events'],
    );
  }

  /**
   * An unknown event name is refused on save and nothing persists.
   *
   * If this assertion is deleted, a typo can be stored as a filter
   * that never matches. mcp.entity.save keeps its own copy above.
   */
  public function testUnknownWebhookEventNameRejectedOnSettingsSave(): void {
    $this->seedRetiredSaveWebhookEndpoint();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'webhooks[endpoints][0][events]' => "mcp.entity.update\nMCP.ENTITY.PRESAVE",
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('Endpoint siem filters on mcp.entity.update');
    $this->assertSession()->pageTextContains('Endpoint siem filters on MCP.ENTITY.PRESAVE');
    $this->assertSession()->pageTextContains('which is not a live webhook event');
    $this->assertSession()->pageTextContains('mcp.entity.presave, mcp.entity.delete, mcp.anomaly.alert');
    $this->assertSame(
      ['mcp.entity.save'],
      \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints')[0]['events'],
    );
  }

  /**
   * A settings-form filter change writes a webhook_event_filter row.
   */
  public function testWebhookEventFilterChangeWritesAuditRow(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => '',
        'events' => ['mcp.entity.delete'],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'webhooks[endpoints][0][events]' => 'mcp.entity.presave',
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $meta = $this->latestWebhookEventFilterAudit();
    $this->assertSame('siem', $meta['endpoint_id']);
    $this->assertSame('changed', $meta['change']);
    $this->assertSame(['mcp.entity.delete'], $meta['from']);
    $this->assertSame(['mcp.entity.presave'], $meta['to']);
  }

  /**
   * Adding an endpoint writes change=added, not an empty-filter from.
   */
  public function testAddingWebhookEndpointWritesAddedFilterAudit(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [])
      ->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'webhooks[endpoints][0][id]' => 'siem',
      'webhooks[endpoints][0][label]' => 'SIEM',
      'webhooks[endpoints][0][url]' => 'https://siem.example.com/hook',
      'webhooks[endpoints][0][events]' => 'mcp.entity.presave',
      'webhooks[endpoints][0][enabled]' => 1,
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $meta = $this->latestWebhookEventFilterAudit();
    $this->assertSame('siem', $meta['endpoint_id']);
    $this->assertSame('added', $meta['change']);
    $this->assertArrayHasKey('from', $meta);
    $this->assertNull($meta['from'], 'Added endpoints did not exist; from must not be [].');
    $this->assertSame(['mcp.entity.presave'], $meta['to']);
  }

  /**
   * Removing an endpoint writes change=removed, not an empty-filter to.
   */
  public function testRemovingWebhookEndpointWritesRemovedFilterAudit(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'siem',
          'label' => 'SIEM',
          'url' => 'https://siem.example.com/hook',
          'secret_key' => '',
          'events' => ['mcp.entity.delete'],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
        ],
        [
          'id' => 'soc',
          'label' => 'SOC',
          'url' => 'https://soc.example.com/hook',
          'secret_key' => '',
          'events' => ['mcp.anomaly.alert'],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
        ],
      ])
      ->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([], 'Remove endpoint 1');
    $this->submitForm([], 'Save configuration');
    $this->assertSession()->pageTextContains('The configuration options have been saved.');
    $this->assertSame(
      ['soc'],
      array_column(
        \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints'),
        'id',
      ),
    );
    $meta = $this->latestWebhookEventFilterAudit();
    $this->assertSame('siem', $meta['endpoint_id']);
    $this->assertSame('removed', $meta['change']);
    $this->assertSame(['mcp.entity.delete'], $meta['from']);
    $this->assertArrayHasKey('to', $meta);
    $this->assertNull($meta['to'], 'Removed endpoints are gone; to must not be [].');
  }

  /**
   * Latest webhook_event_filter metadata, or fail if none.
   *
   * @return array<string, mixed>
   *   Decoded metadata.
   */
  private function latestWebhookEventFilterAudit(): array {
    $db = \Drupal::database();
    $this->assertTrue($db->schema()->tableExists('audit_chain_log'));
    $row = $db->select('audit_chain_log', 'l')
      ->fields('l', ['operation', 'metadata'])
      ->condition('l.operation', 'webhook_event_filter')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row, 'A webhook_event_filter audit row must exist.');
    return \Drupal::service('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
  }

  /**
   * Seeds one endpoint whose filter is the retired mcp.entity.save name.
   */
  private function seedRetiredSaveWebhookEndpoint(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => '',
        'events' => ['mcp.entity.save'],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])
      ->set('dashboard_broadcast', [
        'message' => '',
        'severity' => 'info',
      ])
      ->save();
  }

}
