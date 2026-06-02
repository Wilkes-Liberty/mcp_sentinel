<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Queue\QueueFactory;
use Psr\Log\LoggerInterface;

/**
 * Manages webhook endpoint dispatch via the Drupal queue system.
 *
 * Iterates configured webhook_endpoints, filters by event type and enabled
 * flag, writes a pending delivery log row (including the full JSON payload for
 * faithful replay), then enqueues the item for the McpWebhookWorker QueueWorker
 * plugin to process. A fast (DNS-free) SSRF check runs here (Layer 1); the
 * worker re-validates with DNS resolution (Layer 2) at send time, since DNS
 * can rebind between enqueue and delivery.
 */
final class McpWebhookQueueManager {

  /**
   * The queue name shared with the McpWebhookWorker QueueWorker plugin.
   */
  public const QUEUE_NAME = 'mcp_sentinel_webhook_delivery';

  /**
   * Maximum bytes stored in the payload column (safety cap for large payloads).
   *
   * Entity-event payloads are typically small; this bound guards against
   * pathological cases (e.g. huge metadata arrays).
   */
  private const MAX_PAYLOAD_BYTES = 65535;

  /**
   * Constructs a new McpWebhookQueueManager.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\Queue\QueueFactory $queueFactory
   *   The queue factory.
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The MCP Sentinel logger channel.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly QueueFactory $queueFactory,
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Enqueues delivery items for all matching enabled endpoints.
   *
   * @param string $eventName
   *   The MCP event identifier.
   * @param array $payload
   *   The event payload (will be JSON-encoded for delivery).
   */
  public function enqueueForEvent(string $eventName, array $payload): void {
    $endpoints = (array) $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('webhook_endpoints');
    foreach ($endpoints as $endpoint) {
      if (empty($endpoint['enabled'])) {
        continue;
      }
      $events = (array) ($endpoint['events'] ?? []);
      if ($events && !in_array($eventName, $events, TRUE)) {
        continue;
      }
      $url = (string) ($endpoint['url'] ?? '');
      if (!str_starts_with($url, 'https://')) {
        $this->logger->error(
          'Webhook endpoint @id skipped: URL must use HTTPS.',
          ['@id' => $endpoint['id'] ?? ''],
        );
        continue;
      }
      // Fast Layer-1 SSRF check (no DNS).
      if ($this->isFastBlockedHost($url)) {
        $this->logger->error(
          'Webhook endpoint @id skipped at enqueue: hostname blocked by SSRF guard.',
          ['@id' => $endpoint['id'] ?? ''],
        );
        continue;
      }
      $this->enqueueEndpoint($endpoint, $eventName, $payload);
    }
  }

  /**
   * Re-enqueues pending rows whose next_attempt is now due.
   *
   * This is the Fix-6 cron scan that replaces the RequeueException busy-loop.
   * Instead of re-queuing a not-yet-due item immediately (causing every cron
   * run to pick it up and throw RequeueException until backoff elapses), the
   * worker now simply returns without re-queuing. This cron scan then picks up
   * rows whose next_attempt has elapsed, as well as rows that were inserted but
   * never successfully enqueued (lost-delivery recovery).
   *
   * Only rows in 'pending' status with next_attempt <= now (or NULL, for rows
   * in the initial pending state before any attempt) are processed.
   *
   * @return int
   *   Number of rows re-enqueued.
   */
  public function requeueDuePendingRows(): int {
    $now = $this->time->getRequestTime();
    // Fetch pending rows that are either newly created (next_attempt IS NULL)
    // or whose backoff has elapsed.
    $rows = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['id', 'endpoint_id', 'event_name', 'payload'])
      ->condition('d.status', 'pending')
      ->condition(
        $this->database->condition('OR')
          ->isNull('d.next_attempt')
          ->condition('d.next_attempt', $now, '<='),
      )
      ->execute()
      ->fetchAll();

    $queue = $this->queueFactory->get(self::QUEUE_NAME);
    $count = 0;
    foreach ($rows as $row) {
      $endpoint = $this->findEndpoint((string) $row->endpoint_id);
      if ($endpoint === NULL) {
        continue;
      }
      // Use the stored payload; fall back to empty string for legacy rows.
      $payloadJson = (string) ($row->payload ?? '');
      $itemId = $queue->createItem([
        'delivery_id' => (int) $row->id,
        'endpoint'    => $endpoint,
        'event_name'  => (string) $row->event_name,
        'payload'     => $payloadJson,
      ]);
      if ($itemId !== FALSE) {
        $this->database->update('mcp_sentinel_webhook_delivery')
          ->condition('id', (int) $row->id)
          ->fields(['item_id' => $itemId])
          ->execute();
        $count++;
      }
    }
    return $count;
  }

  /**
   * Prunes delivery rows older than the configured retention period.
   *
   * @return int
   *   Number of rows deleted.
   */
  public function pruneOldDeliveries(): int {
    $days = (int) $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('webhook_delivery_retention_days');
    if ($days <= 0) {
      return 0;
    }
    $cutoff = $this->time->getRequestTime() - ($days * 86400);
    return (int) $this->database->delete('mcp_sentinel_webhook_delivery')
      ->condition('created', $cutoff, '<')
      ->execute();
  }

  /**
   * Re-enqueues an existing delivery row for replay.
   *
   * Resets the row to a clean pending state and pushes a fresh queue item so
   * the worker re-attempts delivery. The stored payload is re-used byte-for-
   * byte so receivers see the exact original body. The endpoint config is
   * re-resolved from current settings (an endpoint removed since the original
   * send is skipped).
   *
   * @param int $deliveryId
   *   The delivery log row ID to replay.
   *
   * @return bool
   *   TRUE if the row was found and re-enqueued, FALSE otherwise.
   */
  public function replayDelivery(int $deliveryId): bool {
    $row = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')
      ->condition('d.id', $deliveryId)
      ->execute()
      ->fetchAssoc();
    if (!$row) {
      return FALSE;
    }
    $endpoint = $this->findEndpoint((string) $row['endpoint_id']);
    if ($endpoint === NULL) {
      $this->logger->warning(
        'Cannot replay delivery @id: endpoint @ep no longer configured.',
        ['@id' => $deliveryId, '@ep' => $row['endpoint_id']],
      );
      return FALSE;
    }

    // Use the stored payload for byte-identical replay. Legacy rows that
    // predate payload storage have an empty column; warn and fall back to
    // a minimal envelope so the row can still be re-queued.
    $payloadJson = (string) ($row['payload'] ?? '');
    if ($payloadJson === '') {
      $this->logger->warning(
        'Replay of delivery @id: no stored payload (legacy row); sending minimal envelope.',
        ['@id' => $deliveryId],
      );
      $payloadJson = $this->buildLegacyFallbackPayload($row, $endpoint);
    }

    $this->database->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $deliveryId)
      ->fields([
        'status'             => 'pending',
        'attempts'           => 0,
        'next_attempt'       => NULL,
        'last_attempt'       => NULL,
        'last_response_code' => NULL,
        'last_response_body' => NULL,
      ])->execute();

    $queue = $this->queueFactory->get(self::QUEUE_NAME);
    $itemId = $queue->createItem([
      'delivery_id' => $deliveryId,
      'endpoint'    => $endpoint,
      'event_name'  => (string) $row['event_name'],
      'payload'     => $payloadJson,
    ]);
    if ($itemId !== FALSE) {
      $this->database->update('mcp_sentinel_webhook_delivery')
        ->condition('id', $deliveryId)
        ->fields(['item_id' => $itemId])
        ->execute();
    }
    return TRUE;
  }

  /**
   * Writes a pending delivery row and enqueues a worker item for one endpoint.
   *
   * The full JSON payload is stored in the delivery row (capped at
   * MAX_PAYLOAD_BYTES) so that replay sends the exact original body rather than
   * a synthetic envelope.
   *
   * @param array $endpoint
   *   The endpoint configuration map.
   * @param string $eventName
   *   The MCP event identifier.
   * @param array $payload
   *   The event payload.
   */
  private function enqueueEndpoint(
    array $endpoint,
    string $eventName,
    array $payload,
  ): void {
    try {
      $payloadJson = json_encode($payload, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException $e) {
      $this->logger->error('Webhook payload encode failed: @msg',
        ['@msg' => $e->getMessage()]);
      return;
    }
    // Cap the stored payload to MAX_PAYLOAD_BYTES. Entity-event payloads are
    // small in practice; this bound protects against pathological edge cases.
    $storedPayload = strlen($payloadJson) <= self::MAX_PAYLOAD_BYTES
      ? $payloadJson
      : substr($payloadJson, 0, self::MAX_PAYLOAD_BYTES);

    $now = $this->time->getRequestTime();
    $rowId = (int) $this->database
      ->insert('mcp_sentinel_webhook_delivery')
      ->fields([
        'endpoint_id'  => substr((string) ($endpoint['id'] ?? ''), 0, 64),
        'event_name'   => substr($eventName, 0, 128),
        'payload_hash' => hash('sha256', $payloadJson),
        'payload'      => $storedPayload,
        'status'       => 'pending',
        'attempts'     => 0,
        'created'      => $now,
      ])->execute();

    $queue = $this->queueFactory->get(self::QUEUE_NAME);
    $itemId = $queue->createItem([
      'delivery_id' => $rowId,
      'endpoint'    => $endpoint,
      'event_name'  => $eventName,
      'payload'     => $payloadJson,
    ]);
    if ($itemId !== FALSE) {
      $this->database->update('mcp_sentinel_webhook_delivery')
        ->condition('id', $rowId)
        ->fields(['item_id' => $itemId])
        ->execute();
    }
  }

  /**
   * Builds a minimal fallback JSON envelope for legacy rows without a payload.
   *
   * Pre-Fix-4 delivery rows do not have a stored payload. When such a row is
   * replayed, this fallback envelope is sent instead of the original body.
   * Receivers should verify the HMAC over this exact string.
   *
   * @param array $row
   *   The delivery log row.
   * @param array $endpoint
   *   The resolved endpoint configuration.
   *
   * @return string
   *   The JSON-encoded fallback payload.
   */
  private function buildLegacyFallbackPayload(array $row, array $endpoint): string {
    $payload = [
      'event'       => (string) $row['event_name'],
      'replay'      => TRUE,
      'delivery_id' => (int) $row['id'],
      'endpoint'    => (string) ($endpoint['id'] ?? ''),
      'timestamp'   => $this->time->getRequestTime(),
    ];
    try {
      return json_encode($payload, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      return '{}';
    }
  }

  /**
   * Resolves a configured endpoint by its machine ID.
   *
   * @param string $endpointId
   *   The endpoint machine ID.
   *
   * @return array|null
   *   The endpoint configuration map, or NULL if not found.
   */
  private function findEndpoint(string $endpointId): ?array {
    $endpoints = (array) $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('webhook_endpoints');
    foreach ($endpoints as $endpoint) {
      if ((string) ($endpoint['id'] ?? '') === $endpointId) {
        return $endpoint;
      }
    }
    return NULL;
  }

  /**
   * Layer-1 SSRF check: blocks obvious internal hosts without DNS resolution.
   *
   * @param string $url
   *   The endpoint URL.
   *
   * @return bool
   *   TRUE if the host is an obvious internal/loopback literal.
   */
  private function isFastBlockedHost(string $url): bool {
    $host = strtolower((string) parse_url($url, PHP_URL_HOST));
    $host = trim($host, '[]');
    if (in_array($host, ['localhost', '::1', '0.0.0.0'], TRUE)) {
      return TRUE;
    }
    foreach (['127.', '0.0.0.0', '::1'] as $blocked) {
      if (str_starts_with($host, $blocked)) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
