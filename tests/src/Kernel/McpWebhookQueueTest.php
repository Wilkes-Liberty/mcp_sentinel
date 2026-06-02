<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the webhook delivery log table and queue manager dispatch.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpWebhookQueueManager
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpWebhookQueueTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'key',
    'tool',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_webhook_delivery']);
    $this->installConfig(['mcp_sentinel']);
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * The delivery log table is created by the module schema.
   */
  public function testDeliveryLogTableExists(): void {
    $this->assertTrue(
      \Drupal::database()->schema()->tableExists('mcp_sentinel_webhook_delivery')
    );
  }

  /**
   * The webhook_endpoints setting exists and defaults to an array.
   */
  public function testWebhookEndpointsSettingExists(): void {
    $this->assertIsArray(
      \Drupal::config('mcp_sentinel.settings')->get('webhook_endpoints')
    );
  }

  /**
   * Dispatch enqueues a pending delivery for an enabled, matching endpoint.
   *
   * @covers ::enqueueForEvent
   */
  public function testDispatchEnqueuesForEnabledEndpoint(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'ep1',
          'label' => 'Test',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
        ],
      ])->save();

    $node = Node::create(['type' => 'page', 'title' => 'T', 'uid' => 1]);
    \Drupal::service('mcp_sentinel.event_dispatcher')
      ->dispatch('mcp.entity.presave', $node);

    $queue = \Drupal::queue('mcp_sentinel_webhook_delivery');
    $this->assertSame(1, $queue->numberOfItems());

    $row = \Drupal::database()->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->execute()->fetchAssoc();
    $this->assertSame('pending', $row['status']);
    $this->assertSame('ep1', $row['endpoint_id']);
    $this->assertSame('mcp.entity.presave', $row['event_name']);
  }

  /**
   * A disabled endpoint produces no queue item.
   *
   * @covers ::enqueueForEvent
   */
  public function testDisabledEndpointNotEnqueued(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'ep1',
          'label' => 'Off',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => FALSE,
        ],
      ])->save();

    $node = Node::create(['type' => 'page', 'title' => 'T', 'uid' => 1]);
    \Drupal::service('mcp_sentinel.event_dispatcher')
      ->dispatch('mcp.entity.presave', $node);

    $this->assertSame(
      0,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems()
    );
  }

  /**
   * Per-event filtering: an endpoint only receives events it lists.
   *
   * @covers ::enqueueForEvent
   */
  public function testEventTypeFilteringSelectsEndpoints(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'deletes_only',
          'label' => 'Deletes',
          'url' => 'https://example.com/del',
          'secret_key' => '',
          'events' => ['mcp.entity.delete'],
          'enabled' => TRUE,
        ],
        [
          'id' => 'all_events',
          'label' => 'All',
          'url' => 'https://example.com/all',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
        ],
      ])->save();

    $node = Node::create(['type' => 'page', 'title' => 'T', 'uid' => 1]);
    \Drupal::service('mcp_sentinel.event_dispatcher')
      ->dispatch('mcp.entity.presave', $node);

    // Only the all-events endpoint should match a presave event.
    $rows = \Drupal::database()->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['endpoint_id'])->execute()->fetchCol();
    $this->assertSame(['all_events'], $rows);
    $this->assertSame(
      1,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems()
    );
  }

  /**
   * A non-HTTPS endpoint URL is rejected at enqueue time.
   *
   * @covers ::enqueueForEvent
   */
  public function testNonHttpsEndpointRejectedAtEnqueue(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'insecure',
          'label' => 'HTTP',
          'url' => 'http://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
        ],
      ])->save();

    $node = Node::create(['type' => 'page', 'title' => 'T', 'uid' => 1]);
    \Drupal::service('mcp_sentinel.event_dispatcher')
      ->dispatch('mcp.entity.presave', $node);

    $this->assertSame(
      0,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems()
    );
  }

  /**
   * Update_10008 migrates a legacy single webhook into webhook_endpoints.
   */
  public function testUpdate10008MigratesLegacyEndpoint(): void {
    $config = \Drupal::configFactory()->getEditable('mcp_sentinel.settings');
    $config
      ->set('webhook_enabled', TRUE)
      ->set('webhook_url', 'https://legacy.example.com/hook')
      ->set('webhook_secret_key', 'mcp_sentinel_webhook')
      ->set('webhook_endpoints', [])
      ->clear('webhook_delivery_retention_days')
      ->save();

    require_once \Drupal::root() . '/' . \Drupal::service('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';
    mcp_sentinel_update_10008();

    $reloaded = \Drupal::configFactory()->get('mcp_sentinel.settings');
    $endpoints = $reloaded->get('webhook_endpoints');
    $this->assertCount(1, $endpoints);
    $this->assertSame('default', $endpoints[0]['id']);
    $this->assertSame('https://legacy.example.com/hook', $endpoints[0]['url']);
    $this->assertSame('mcp_sentinel_webhook', $endpoints[0]['secret_key']);
    $this->assertTrue($endpoints[0]['enabled']);
    $this->assertSame([], $endpoints[0]['events']);
    $this->assertSame(30, $reloaded->get('webhook_delivery_retention_days'));
    // Legacy keys are retained.
    $this->assertSame('https://legacy.example.com/hook', $reloaded->get('webhook_url'));
  }

  /**
   * PruneOldDeliveries removes rows older than the retention window.
   *
   * @covers ::pruneOldDeliveries
   */
  public function testPruneRemovesOldRows(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_delivery_retention_days', 30)->save();
    $now = \Drupal::time()->getRequestTime();
    $db = \Drupal::database();
    // One old, one fresh.
    $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep',
      'event_name' => 'e',
      'payload_hash' => 'h',
      'status' => 'sent',
      'attempts' => 1,
      'created' => $now - (40 * 86400),
    ])->execute();
    $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep',
      'event_name' => 'e',
      'payload_hash' => 'h',
      'status' => 'sent',
      'attempts' => 1,
      'created' => $now - (5 * 86400),
    ])->execute();

    $deleted = \Drupal::service('mcp_sentinel.webhook_queue_manager')
      ->pruneOldDeliveries();
    $this->assertSame(1, $deleted);
    $this->assertSame(
      1,
      (int) $db->select('mcp_sentinel_webhook_delivery')->countQuery()
        ->execute()->fetchField()
    );
  }

}
