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
   */
  private function seedRow(string $status, int $attempts = 0): int {
    return (int) \Drupal::database()
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'        => 'ep1',
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
