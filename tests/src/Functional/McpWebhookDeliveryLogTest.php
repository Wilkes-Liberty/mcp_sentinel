<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests the webhook delivery log listing page and replay action.
 *
 * @group mcp_sentinel
 */
final class McpWebhookDeliveryLogTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Seeds a delivery row and returns its ID.
   *
   * @param string $status
   *   Delivery status.
   * @param int $attempts
   *   Number of delivery attempts.
   * @param string $endpointId
   *   Endpoint identifier (defaults to 'ep1').
   */
  private function seedRow(
    string $status,
    int $attempts = 0,
    string $endpointId = 'ep1',
  ): int {
    return (int) \Drupal::database()
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'        => $endpointId,
        'event_name'         => 'mcp.entity.presave',
        'payload_hash'       => hash('sha256', '{}'),
        'payload'            => '{}',
        'status'             => $status,
        'attempts'           => $attempts,
        'last_response_code' => 500,
        'created'            => \Drupal::time()->getRequestTime(),
      ])->execute();
  }

  /**
   * The listing page renders seeded delivery rows for an admin.
   */
  public function testDeliveryLogListingShowsRows(): void {
    $this->seedRow('failed', 5);
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('ep1');
    $this->assertSession()->pageTextContains('mcp.entity.presave');
    $this->assertSession()->pageTextContains('failed');
    $this->assertSession()->pageTextContains('Replay');
  }

  /**
   * A user without the permission is denied access to the listing.
   */
  public function testDeliveryLogRequiresPermission(): void {
    $user = $this->drupalCreateUser([]);
    $this->drupalLogin($user);
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * D2: Status badges render and the filter select is present on the listing.
   */
  public function testStatusBadgesAndFilterRender(): void {
    $this->seedRow('failed');
    $this->seedRow('sent');
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->assertSession()->elementExists('css', '.mcp-badge--crit');
    $this->assertSession()->fieldExists('status');
  }

  /**
   * D2: Status filter narrows the rows shown in the table.
   *
   * Uses unique endpoint IDs to distinguish rows, avoiding the "sent" ↔
   * "sentinel" false-positive in pageTextNotContains.
   */
  public function testStatusFilterNarrowsRows(): void {
    // Seed a 'failed' row tied to 'ep_failed_only' and a 'sent' row to
    // 'ep_delivered_only' so we can assert each by its endpoint ID.
    $this->seedRow('failed', 0, 'ep_failed_only');
    $this->seedRow('sent', 0, 'ep_delivered_only');
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks', [
      'query' => ['status' => 'failed'],
    ]);
    $this->assertSession()->pageTextContains('ep_failed_only');
    $this->assertSession()->pageTextNotContains('ep_delivered_only');
  }

  /**
   * D2: Prune delivery log action link is present on the listing.
   */
  public function testPruneActionPresent(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->assertSession()->linkExists('Prune delivery log');
  }

  /**
   * The Replay link re-enqueues the delivery (reset to pending, attempts=0).
   */
  public function testReplayResetsDelivery(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [
        [
          'id'             => 'ep1',
          'label'          => 'EP1',
          'url'            => 'https://example.com/hook',
          'secret_key'     => '',
          'events'         => [],
          'enabled'        => TRUE,
          'allow_internal' => FALSE,
        ],
      ])->save();
    $id = $this->seedRow('failed', 5);
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->clickLink('Replay');
    $this->assertSession()->statusCodeEquals(200);

    $row = \Drupal::database()->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $id)->execute()->fetchAssoc();
    $this->assertSame('pending', $row['status']);
    $this->assertSame('0', (string) $row['attempts']);
    $this->assertSame(
      1,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems()
    );
  }

}
