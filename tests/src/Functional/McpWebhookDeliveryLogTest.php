<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Component\Utility\Crypt;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drupal\Tests\BrowserTestBase;
use Symfony\Component\HttpFoundation\Request;

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
   * @param string $eventName
   *   Stored event name (defaults to a live name).
   */
  private function seedRow(
    string $status,
    int $attempts = 0,
    string $endpointId = 'ep1',
    string $eventName = 'mcp.entity.presave',
  ): int {
    return (int) \Drupal::database()
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'        => $endpointId,
        'event_name'         => $eventName,
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

  /**
   * Replay of a stored unknown event_name names the refused event.
   */
  public function testReplayRefusedUnknownEventName(): void {
    $id = $this->seedRow('failed', 1, 'ep1', 'mcp.not.a.live.event');
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->clickLink('Replay');
    $this->assertSession()->pageTextContains(
      "Delivery $id could not be replayed: event name mcp.not.a.live.event was refused.",
    );
    $row = \Drupal::database()->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')->condition('d.id', $id)->execute()->fetchAssoc();
    $this->assertSame(McpWebhookQueueManager::STATUS_FAILED, $row['status']);
    $this->assertSame(
      0,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems(),
    );
  }

  /**
   * Replay of a held unknown name names the status, not a refusal.
   *
   * Held and discarded rows have no Replay link. The wording is
   * reached through the CSRF-tokened route. linkNotExists('Replay')
   * fails if that link is put back on the listing.
   */
  public function testReplayHeldUnknownEventNameNamesStatus(): void {
    $heldId = $this->seedRow(
      McpWebhookQueueManager::STATUS_HELD,
      1,
      'ep_held',
      'mcp.not.a.live.event',
    );
    $discardedId = $this->seedRow(
      McpWebhookQueueManager::STATUS_DISCARDED,
      1,
      'ep_discarded',
      'mcp.not.a.live.event',
    );
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/reports/mcp-sentinel/webhooks');
    $this->assertSession()->pageTextContains('ep_held');
    $this->assertSession()->pageTextContains('ep_discarded');
    $this->assertSession()->linkNotExists('Replay');
    $this->assertSession()->elementNotExists(
      'css',
      'a[href*="/webhooks/' . $heldId . '/replay"]',
    );
    $this->assertSession()->elementNotExists(
      'css',
      'a[href*="/webhooks/' . $discardedId . '/replay"]',
    );

    $route = $this->container->get('router.route_provider')
      ->getRouteByName('mcp_sentinel.webhook_replay');
    $path = ltrim(strtr($route->getPath(), [
      '{delivery}' => (string) $heldId,
    ]), '/');
    $token = $this->csrfTokenForBrowserPath($path);
    $this->drupalGet(
      $this->getAbsoluteUrl('/' . $path) . '?token=' . rawurlencode($token),
    );
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains(
      "Delivery $heldId could not be replayed (" . McpWebhookQueueManager::STATUS_HELD . ').',
    );
    $this->assertSession()->pageTextNotContains('was refused');
    $this->assertSame(
      0,
      \Drupal::queue('mcp_sentinel_webhook_delivery')->numberOfItems(),
    );
  }

  /**
   * CSRF token for $path using the browser session seed.
   *
   * The test container's csrf_token service has a different
   * session from the logged-in browser, so a token minted
   * there is rejected. The seed is read from the stored
   * session payload; unserialize() is not used because the
   * PHP session format warns on extra data.
   *
   * @param string $path
   *   Route path without a leading slash.
   *
   * @return string
   *   Token valid for the browser session.
   */
  private function csrfTokenForBrowserPath(string $path): string {
    $blob = $this->browserSessionBlob();
    $seed = '';
    if (preg_match('/s:1:"s";s:\d+:"([A-Za-z0-9_-]+)"/', $blob, $matches) === 1) {
      $seed = $matches[1];
    }
    $this->assertNotSame('', $seed, 'Session blob prefix: ' . substr($blob, 0, 200));
    $this->container->get('session_manager.metadata_bag')
      ->setCsrfTokenSeed($seed);
    return $this->container->get('csrf_token')->get($path);
  }

  /**
   * Serialized session for the logged-in browser user.
   *
   * The cookie name is hashed from the test-site base URL so it
   * matches the browser cookie. The uid row is the fallback.
   *
   * @return string
   *   Stored session payload.
   */
  private function browserSessionBlob(): string {
    $request = Request::create(rtrim((string) $this->baseUrl, '/') . '/');
    $options = $this->container->get('session_configuration')
      ->getOptions($request);
    $name = is_array($options) && isset($options['name']) && is_string($options['name'])
      ? $options['name']
      : '';
    $sid = $name !== '' ? (string) $this->getSession()->getCookie($name) : '';
    if ($sid !== '') {
      $blob = (string) $this->container->get('session_handler.storage')
        ->read($sid);
      if ($blob !== '') {
        return $blob;
      }
      $blob = (string) \Drupal::database()
        ->select('sessions', 's')
        ->fields('s', ['session'])
        ->condition('sid', Crypt::hashBase64($sid))
        ->execute()
        ->fetchField();
      if ($blob !== '') {
        return $blob;
      }
    }
    $account = $this->loggedInUser;
    $this->assertNotFalse($account);
    $blob = (string) \Drupal::database()
      ->select('sessions', 's')
      ->fields('s', ['session'])
      ->condition('uid', (int) $account->id())
      ->orderBy('timestamp', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchField();
    $this->assertNotSame('', $blob);
    return $blob;
  }

}
