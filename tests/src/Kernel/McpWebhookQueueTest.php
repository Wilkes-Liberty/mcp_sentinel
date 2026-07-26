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
 *
 * @runTestsInSeparateProcesses
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
    // Requirements descriptions build routed URLs; URL generation consults
    // the alias repository, which needs the path_alias storage.
    $this->installEntitySchema('path_alias');
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_webhook_delivery']);
    $this->installConfig(['mcp_sentinel']);
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * Inserts a delivery row with the given status fields (test helper).
   */
  private function seedDeliveryRow(array $overrides = []): int {
    $now = \Drupal::time()->getRequestTime();
    return (int) $this->container->get('database')
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields($overrides + [
        'endpoint_id'  => 'ep1',
        'event_name'   => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload'      => '{}',
        'status'       => 'pending',
        'attempts'     => 0,
        'created'      => $now,
      ])->execute();
  }

  /**
   * Cron reclaims rows stranded in_progress by a dead worker (#3613242).
   *
   * @covers \Drupal\mcp_sentinel\Service\McpWebhookQueueManager::reclaimStaleClaims
   */
  public function testReclaimStaleClaims(): void {
    $now = \Drupal::time()->getRequestTime();
    $stale = $this->seedDeliveryRow([
      'status' => 'in_progress',
      'attempts' => 1,
      'last_attempt' => $now - 7200,
    ]);
    $fresh = $this->seedDeliveryRow([
      'status' => 'in_progress',
      'attempts' => 1,
      'last_attempt' => $now - 60,
    ]);

    $reclaimed = $this->container->get('mcp_sentinel.webhook_queue_manager')
      ->reclaimStaleClaims();
    $this->assertSame(1, $reclaimed);

    $db = $this->container->get('database');
    $staleRow = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('id', $stale)->execute()->fetchAssoc();
    // Reclaimed: pending again, with the attempt counter bumped so a row that
    // deterministically kills its worker still converges on MAX_ATTEMPTS.
    $this->assertSame('pending', $staleRow['status']);
    $this->assertSame('2', (string) $staleRow['attempts']);

    $freshRow = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('id', $fresh)->execute()->fetchAssoc();
    // A live claim inside the TTL is untouched.
    $this->assertSame('in_progress', $freshRow['status']);
    $this->assertSame('1', (string) $freshRow['attempts']);
  }

  /**
   * Accumulated permanent delivery failures warn on the status report.
   *
   * #3613242: 1968 permanently failed deliveries once accumulated with no
   * signal anywhere; this pins the hook_requirements() surface that makes the
   * silence loud.
   */
  public function testRequirementsWarnsOnPermanentFailures(): void {
    include_once DRUPAL_ROOT . '/core/includes/install.inc';
    \Drupal::moduleHandler()->loadInclude('mcp_sentinel', 'install');

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayNotHasKey('mcp_sentinel_webhook_failures', $requirements);

    $this->seedDeliveryRow(['status' => 'failed', 'last_attempt' => \Drupal::time()->getRequestTime()]);
    $this->seedDeliveryRow(['status' => 'failed_redirect', 'last_attempt' => \Drupal::time()->getRequestTime()]);

    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_webhook_failures', $requirements);
    $this->assertSame(REQUIREMENT_WARNING, $requirements['mcp_sentinel_webhook_failures']['severity']);
    $this->assertStringContainsString('2', (string) $requirements['mcp_sentinel_webhook_failures']['value']);
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
   * The delivery log table has the payload column (Fix 4).
   */
  public function testDeliveryLogTableHasPayloadColumn(): void {
    $this->assertTrue(
      \Drupal::database()->schema()->fieldExists('mcp_sentinel_webhook_delivery', 'payload'),
      'The payload column must exist for faithful replay.'
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
   * Also verifies the payload is stored in the delivery row (Fix 4).
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
          'allow_internal' => FALSE,
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
    // Fix 4: the payload column must contain valid JSON, not be empty.
    $this->assertNotEmpty($row['payload'],
      'Payload must be stored in the delivery row for faithful replay.');
    $decoded = json_decode($row['payload'], TRUE);
    $this->assertIsArray($decoded,
      'Stored payload must be valid JSON.');
    // payload_hash must match the stored payload.
    $this->assertSame(hash('sha256', $row['payload']), $row['payload_hash'],
      'payload_hash must match hash of stored payload.');
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
          'allow_internal' => FALSE,
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
          'allow_internal' => FALSE,
        ],
        [
          'id' => 'all_events',
          'label' => 'All',
          'url' => 'https://example.com/all',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
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
          'allow_internal' => FALSE,
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
   *
   * Also verifies that the migrated endpoint has allow_internal=FALSE (Fix 5).
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
    // Fix 5: migrated endpoint must have allow_internal=FALSE by default.
    $this->assertFalse($endpoints[0]['allow_internal'],
      'Migrated endpoint must default allow_internal to FALSE.');
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
      'payload' => '{}',
      'status' => 'sent',
      'attempts' => 1,
      'created' => $now - (40 * 86400),
    ])->execute();
    $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id' => 'ep',
      'event_name' => 'e',
      'payload_hash' => 'h',
      'payload' => '{}',
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

  /**
   * Fix 6: requeueDuePendingRows re-enqueues due pending rows only.
   *
   * @covers ::requeueDuePendingRows
   */
  public function testRequeueDuePendingRowsEnqueuesDueRows(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'ep1',
          'label' => 'Test',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
        ],
      ])->save();

    $now = \Drupal::time()->getRequestTime();
    $db = \Drupal::database();

    // Row 1: due now (next_attempt in the past).
    $dueId = (int) $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id'  => 'ep1',
      'event_name'   => 'mcp.entity.presave',
      'payload_hash' => hash('sha256', '{}'),
      'payload'      => '{}',
      'status'       => 'pending',
      'attempts'     => 1,
      'next_attempt' => $now - 10,
      'created'      => $now,
    ])->execute();

    // Row 2: not yet due (next_attempt in the future).
    $notDueId = (int) $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id'  => 'ep1',
      'event_name'   => 'mcp.entity.presave',
      'payload_hash' => hash('sha256', '{}'),
      'payload'      => '{}',
      'status'       => 'pending',
      'attempts'     => 1,
      'next_attempt' => $now + 3600,
      'created'      => $now,
    ])->execute();

    // Row 3: fresh (no next_attempt — needs first delivery).
    $freshId = (int) $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id'  => 'ep1',
      'event_name'   => 'mcp.entity.presave',
      'payload_hash' => hash('sha256', '{}'),
      'payload'      => '{}',
      'status'       => 'pending',
      'attempts'     => 0,
      'created'      => $now,
    ])->execute();

    $requeued = \Drupal::service('mcp_sentinel.webhook_queue_manager')
      ->requeueDuePendingRows();

    // Only the due row and the fresh row should be re-enqueued.
    $this->assertSame(2, $requeued,
      'Only due and fresh (no next_attempt) pending rows are re-enqueued.');
    $this->assertSame(
      2,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems()
    );

    // Verify item_id updated for due and fresh rows, not for not-due.
    $dueRow = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $dueId)->execute()->fetchAssoc();
    $notDueRow = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $notDueId)->execute()->fetchAssoc();
    $freshRow = $db->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $freshId)->execute()->fetchAssoc();

    $this->assertNotNull($dueRow['item_id'], 'Due row must have item_id set.');
    $this->assertNull($notDueRow['item_id'], 'Not-due row must NOT be re-enqueued.');
    $this->assertNotNull($freshRow['item_id'], 'Fresh row must have item_id set.');
  }

  /**
   * Fix 4: replayDelivery re-uses the stored payload byte-for-byte.
   *
   * @covers ::replayDelivery
   */
  public function testReplayUsesStoredPayload(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id' => 'ep1',
          'label' => 'Test',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
          'allow_internal' => FALSE,
        ],
      ])->save();

    $originalPayload = '{"event":"mcp.entity.presave","entity_type":"node","entity_id":"99"}';
    $db = \Drupal::database();
    $id = (int) $db->insert('mcp_sentinel_webhook_delivery')->fields([
      'endpoint_id'  => 'ep1',
      'event_name'   => 'mcp.entity.presave',
      'payload_hash' => hash('sha256', $originalPayload),
      'payload'      => $originalPayload,
      'status'       => 'failed',
      'attempts'     => 5,
      'created'      => \Drupal::time()->getRequestTime(),
    ])->execute();

    $replayed = \Drupal::service('mcp_sentinel.webhook_queue_manager')
      ->replayDelivery($id);
    $this->assertTrue($replayed);

    // The queue item must carry the original payload.
    $queue = \Drupal::queue('mcp_sentinel_webhook_delivery');
    $item = $queue->claimItem();
    $this->assertNotFalse($item, 'A queue item must be created by replay.');
    \assert(is_object($item));
    $this->assertSame($originalPayload, $item->data['payload'],
      'Replay must enqueue the stored payload byte-for-byte.');
  }

}
