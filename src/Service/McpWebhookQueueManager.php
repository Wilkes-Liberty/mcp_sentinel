<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Queue\QueueFactory;
use Drupal\mcp_sentinel\Enum\McpKillSelectorType;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Psr\Log\LoggerInterface;

/**
 * Manages webhook endpoint dispatch via the Drupal queue system.
 *
 * Iterates configured webhook_endpoints, filters by event type and enabled
 * flag, writes a pending delivery log row (including the full JSON payload for
 * faithful replay), then enqueues the item for the McpWebhookWorker QueueWorker
 * plugin to process. A fast (DNS-free) SSRF check runs here (Layer 1); the
 * worker re-validates with DNS resolution (Layer 2) at send time, since DNS
 * can rebind between enqueue and delivery. Each row stores principal_key,
 * human_key, and tenant at enqueue so a kill can hold in-scope deliveries
 * (DEV-985). Held rows are never re-queued by cron. Release and discard
 * are explicit operator actions.
 */
final class McpWebhookQueueManager {

  /**
   * The queue name shared with the McpWebhookWorker QueueWorker plugin.
   */
  public const QUEUE_NAME = 'mcp_sentinel_webhook_delivery';

  /**
   * Delivery row held after a kill. Never delivered until released.
   */
  public const STATUS_HELD = 'held';

  /**
   * Delivery row discarded by an operator. Never delivered.
   */
  public const STATUS_DISCARDED = 'discarded';

  /**
   * Audit operation for holding in-scope queued deliveries.
   */
  public const AUDIT_HOLD = 'agent_side_effect_hold';

  /**
   * Audit operation for releasing held deliveries.
   */
  public const AUDIT_RELEASE = 'agent_side_effect_release';

  /**
   * Audit operation for discarding held deliveries.
   */
  public const AUDIT_DISCARD = 'agent_side_effect_discard';

  /**
   * PHPUnit-only: cron re-queues held rows.
   */
  public const WEAKEN_REQUEUE_HELD = 'requeue_held';

  /**
   * PHPUnit-only: skip hold/release/discard audit rows.
   */
  public const WEAKEN_SKIP_AUDIT = 'skip_audit';

  /**
   * PHPUnit-only: allow release while the scope is still stopped.
   */
  public const WEAKEN_SKIP_RELEASE_UNDER_STOP = 'skip_release_under_stop';

  /**
   * Maximum bytes stored in the payload column (safety cap for large payloads).
   *
   * Entity-event payloads are typically small; this bound guards against
   * pathological cases (e.g. huge metadata arrays).
   */
  private const MAX_PAYLOAD_BYTES = 65535;

  /**
   * Test-only weaken flags. Empty in production.
   *
   * @var array<string, true>
   */
  private array $weakenForTest = [];

  /**
   * Kill registry used to refuse release under an active stop.
   */
  private ?McpKillSwitch $killSwitch = NULL;

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
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Sealed or carried principal keys stored on each delivery row.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   HMAC audit chain writer.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly QueueFactory $queueFactory,
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly LoggerInterface $logger,
    private readonly McpPrincipalContextHolder $holder,
    private readonly McpAuditLogger $auditLogger,
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
    $status = $this->weakened(self::WEAKEN_REQUEUE_HELD)
      ? ['pending', self::STATUS_HELD]
      : ['pending'];
    $query = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', [
        'id',
        'endpoint_id',
        'event_name',
        'payload',
        'principal_key',
        'human_key',
        'tenant',
      ]);
    $query->condition('d.status', $status, 'IN');
    $query->condition(
      $this->database->condition('OR')
        ->isNull('d.next_attempt')
        ->condition('d.next_attempt', $now, '<='),
    );
    $rows = $query->execute()->fetchAll();

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
        'principal_key' => (string) ($row->principal_key ?? ''),
        'human_key' => (string) ($row->human_key ?? ''),
        'tenant' => (string) ($row->tenant ?? ''),
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
   * Reclaims delivery rows stranded in 'in_progress' by a dead worker.
   *
   * The worker claims a row (pending -> in_progress) before POSTing; if the
   * process dies between the claim and the result write (cron killed, fatal),
   * the row stays in_progress forever — the cron re-enqueue scan only picks
   * up 'pending' (#3613242). Any claim older than the TTL is from a dead
   * worker (a live attempt finishes within the 10s HTTP timeout), so reset it
   * to pending for the scan to re-enqueue. The attempt counter is incremented
   * so a row that deterministically kills its worker still converges on the
   * MAX_ATTEMPTS terminal failure instead of looping forever.
   *
   * @param int $claimTtl
   *   Seconds after which an in_progress claim counts as abandoned.
   *
   * @return int
   *   Number of rows reclaimed.
   */
  public function reclaimStaleClaims(int $claimTtl = 3600): int {
    $now = $this->time->getRequestTime();
    $reclaimed = (int) $this->database->update('mcp_sentinel_webhook_delivery')
      ->condition('status', 'in_progress')
      ->condition('last_attempt', $now - $claimTtl, '<')
      ->fields(['status' => 'pending'])
      ->expression('attempts', 'attempts + 1')
      ->execute();
    if ($reclaimed > 0) {
      $this->logger->warning(
        'Reclaimed @count webhook delivery row(s) stranded in_progress by a dead worker.',
        ['@count' => $reclaimed],
      );
    }
    return $reclaimed;
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
    if (in_array((string) $row['status'], [self::STATUS_HELD, self::STATUS_DISCARDED], TRUE)) {
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
      'principal_key' => (string) ($row['principal_key'] ?? ''),
      'human_key' => (string) ($row['human_key'] ?? ''),
      'tenant' => (string) ($row['tenant'] ?? ''),
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
    [$principalKey, $humanKey, $tenant] = $this->currentPrincipalKeys();
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
        'principal_key' => substr($principalKey, 0, 770),
        'human_key' => substr($humanKey, 0, 770),
        'tenant' => substr($tenant, 0, 128),
      ])->execute();

    $queue = $this->queueFactory->get(self::QUEUE_NAME);
    $itemId = $queue->createItem([
      'delivery_id' => $rowId,
      'endpoint'    => $endpoint,
      'event_name'  => $eventName,
      'payload'     => $payloadJson,
      'principal_key' => $principalKey,
      'human_key' => $humanKey,
      'tenant' => $tenant,
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

  /**
   * Injects the kill registry after construction (avoids a service cycle).
   */
  public function setKillSwitch(McpKillSwitch $killSwitch): void {
    $this->killSwitch = $killSwitch;
  }

  /**
   * Holds pending deliveries that match the kill scope.
   *
   * In-flight (in_progress) POSTs are not recalled. Writes exactly
   * one hold audit row when any item is held.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Kill selectors.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Acting operator.
   * @param string $batchId
   *   Kill batch id (correlation).
   *
   * @return list<int>
   *   Held delivery ids.
   */
  public function holdMatching(array $selectors, McpOperatorIdentity $operator, string $batchId): array {
    if (!$this->database->schema()->tableExists('mcp_sentinel_webhook_delivery')) {
      return [];
    }
    $ids = [];
    foreach ($selectors as $selector) {
      $column = match ($selector->type) {
        McpKillSelectorType::PrincipalKey => 'principal_key',
        McpKillSelectorType::HumanKey => 'human_key',
        McpKillSelectorType::Tenant => 'tenant',
      };
      $statement = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
        ->fields('d', ['id'])
        ->condition($column, $selector->key)
        ->condition('status', 'pending')
        ->execute();
      if ($statement === NULL) {
        continue;
      }
      foreach ($statement->fetchCol() as $id) {
        $ids[] = (int) $id;
      }
    }
    $ids = array_values(array_unique($ids));
    if ($ids === []) {
      return [];
    }
    $this->database->update('mcp_sentinel_webhook_delivery')
      ->fields([
        'status' => self::STATUS_HELD,
        'released' => 0,
      ])
      ->condition('id', $ids, 'IN')
      ->condition('status', 'pending')
      ->execute();
    $this->auditSideEffect(self::AUDIT_HOLD, $operator, $selectors, $ids, $batchId);
    return $ids;
  }

  /**
   * Marks one pending row held because the worker saw an active kill.
   *
   * Writes one AUDIT_HOLD row: operator system, scope, matching
   * kill batch_id.
   */
  public function markHeld(int $deliveryId): void {
    $this->holdFromStatus($deliveryId, 'pending');
  }

  /**
   * Holds a just-claimed in_progress row after a post-claim kill check.
   */
  public function holdClaimed(int $deliveryId): void {
    $this->holdFromStatus($deliveryId, 'in_progress');
  }

  /**
   * Held delivery rows for the Drupal-side UI (DEV-925).
   *
   * @return list<array<string, mixed>>
   *   Associative rows.
   */
  public function listHeld(): array {
    if (!$this->database->schema()->tableExists('mcp_sentinel_webhook_delivery')) {
      return [];
    }
    $statement = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')
      ->condition('status', self::STATUS_HELD)
      ->orderBy('id')
      ->execute();
    if ($statement === NULL) {
      return [];
    }
    $rows = [];
    while ($row = $statement->fetchAssoc()) {
      $rows[] = $row;
    }
    return $rows;
  }

  /**
   * Releases held deliveries so they deliver as originally queued.
   *
   * Same payload, same delivery id. Signature is recomputed at send
   * over that unchanged body.
   *
   * @param list<int> $deliveryIds
   *   Held row ids.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Acting operator.
   * @param string $batchId
   *   Kill batch id used as the release correlation.
   *
   * @return list<int>
   *   Released ids.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function releaseHeld(array $deliveryIds, McpOperatorIdentity $operator, string $batchId = ''): array {
    return $this->finishHeld($deliveryIds, $operator, 'release', $batchId);
  }

  /**
   * Discards held deliveries. They are never delivered.
   *
   * @param list<int> $deliveryIds
   *   Held row ids.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Acting operator.
   *
   * @return list<int>
   *   Discarded ids.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  public function discardHeld(array $deliveryIds, McpOperatorIdentity $operator, string $batchId = ''): array {
    return $this->finishHeld($deliveryIds, $operator, 'discard', $batchId);
  }

  /**
   * PHPUnit-only injection that disables one hold invariant.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function weakenForTest(string $flag): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Webhook-hold weaken flags can be set only under PHPUnit.',
      );
    }
    $this->weakenForTest[$flag] = TRUE;
  }

  /**
   * Releases or discards held rows and writes one audit entry.
   *
   * @param list<int> $deliveryIds
   *   Candidate ids.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Acting operator.
   * @param string $action
   *   Release or discard.
   * @param string $batchId
   *   Kill batch or correlation id.
   *
   * @return list<int>
   *   Affected ids.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function finishHeld(array $deliveryIds, McpOperatorIdentity $operator, string $action, string $batchId = ''): array {
    if (!$operator->isVerified()) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $ids = [];
    foreach ($deliveryIds as $id) {
      $id = (int) $id;
      if ($id > 0) {
        $ids[] = $id;
      }
    }
    $ids = array_values(array_unique($ids));
    if ($ids === []) {
      throw new McpKillSwitchException(
        McpKillSwitchException::NOT_HELD,
        'A held delivery id is required.',
      );
    }
    $rows = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')
      ->condition('id', $ids, 'IN')
      ->condition('status', self::STATUS_HELD)
      ->execute()
      ?->fetchAllAssoc('id') ?? [];
    if ($rows === []) {
      throw new McpKillSwitchException(
        McpKillSwitchException::NOT_HELD,
        'No held delivery matches those ids.',
      );
    }
    $heldIds = array_map(static fn ($id): int => (int) $id, array_keys($rows));
    if ($action === 'release' && !$this->weakened(self::WEAKEN_SKIP_RELEASE_UNDER_STOP)) {
      foreach ($rows as $row) {
        if (!is_array($row)) {
          continue;
        }
        if ($this->rowIsStopped($row)) {
          throw new McpKillSwitchException(
            McpKillSwitchException::SCOPE_STOPPED,
            'Release is refused while the delivery scope is still stopped. Lift or unkill first.',
          );
        }
      }
    }
    if ($action === 'discard') {
      $this->database->update('mcp_sentinel_webhook_delivery')
        ->fields(['status' => self::STATUS_DISCARDED])
        ->condition('id', $heldIds, 'IN')
        ->condition('status', self::STATUS_HELD)
        ->execute();
      $this->auditSideEffect(self::AUDIT_DISCARD, $operator, [], $heldIds, $batchId);
      return $heldIds;
    }
    $this->database->update('mcp_sentinel_webhook_delivery')
      ->fields([
        'status' => 'pending',
        'next_attempt' => NULL,
        'released' => 1,
      ])
      ->condition('id', $heldIds, 'IN')
      ->condition('status', self::STATUS_HELD)
      ->execute();
    $queue = $this->queueFactory->get(self::QUEUE_NAME);
    foreach ($heldIds as $id) {
      $row = $rows[$id] ?? $rows[(string) $id] ?? NULL;
      if (!is_array($row)) {
        continue;
      }
      $endpoint = $this->findEndpoint((string) $row['endpoint_id']);
      if ($endpoint === NULL) {
        continue;
      }
      $itemId = $queue->createItem([
        'delivery_id' => $id,
        'endpoint' => $endpoint,
        'event_name' => (string) $row['event_name'],
        'payload' => (string) ($row['payload'] ?? ''),
        'principal_key' => (string) ($row['principal_key'] ?? ''),
        'human_key' => (string) ($row['human_key'] ?? ''),
        'tenant' => (string) ($row['tenant'] ?? ''),
      ]);
      if ($itemId !== FALSE) {
        $this->database->update('mcp_sentinel_webhook_delivery')
          ->condition('id', $id)
          ->fields(['item_id' => $itemId])
          ->execute();
      }
    }
    $this->auditSideEffect(self::AUDIT_RELEASE, $operator, [], $heldIds, $batchId);
    return $heldIds;
  }

  /**
   * Holds a row from a specific status and writes one hold audit row.
   */
  private function holdFromStatus(int $deliveryId, string $fromStatus): void {
    if ($deliveryId <= 0) {
      return;
    }
    $updated = (int) $this->database->update('mcp_sentinel_webhook_delivery')
      ->condition('id', $deliveryId)
      ->condition('status', $fromStatus)
      ->fields(['status' => self::STATUS_HELD])
      ->execute();
    if ($updated < 1) {
      return;
    }
    $row = $this->database->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d')
      ->condition('id', $deliveryId)
      ->execute()
      ?->fetchAssoc();
    if (!is_array($row)) {
      return;
    }
    $selectors = $this->selectorsFromRow($row);
    $batchId = $this->matchingKillBatchId($selectors);
    $this->auditSideEffect(
      self::AUDIT_HOLD,
      McpOperatorIdentity::system(),
      $selectors,
      [$deliveryId],
      $batchId,
    );
  }

  /**
   * Whether the delivery's keys are still in a stopped scope.
   *
   * @param array<string, mixed> $row
   *   Delivery row.
   */
  private function rowIsStopped(array $row): bool {
    $principalKey = (string) ($row['principal_key'] ?? '');
    $humanKey = (string) ($row['human_key'] ?? '');
    $tenant = (string) ($row['tenant'] ?? '');
    if ($this->killSwitch === NULL) {
      return TRUE;
    }
    return $this->killSwitch->isKilled($principalKey, $humanKey, $tenant);
  }

  /**
   * Selectors stored on a delivery row.
   *
   * @param array<string, mixed> $row
   *   Delivery row.
   *
   * @return list<\Drupal\mcp_sentinel\Value\McpKillSelector>
   *   Non-empty keys from the row.
   */
  private function selectorsFromRow(array $row): array {
    $selectors = [];
    $principalKey = trim((string) ($row['principal_key'] ?? ''));
    $humanKey = trim((string) ($row['human_key'] ?? ''));
    $tenant = trim((string) ($row['tenant'] ?? ''));
    if ($principalKey !== '') {
      $selectors[] = new McpKillSelector(
        McpKillSelectorType::PrincipalKey,
        $principalKey,
      );
    }
    if ($humanKey !== '') {
      $selectors[] = new McpKillSelector(
        McpKillSelectorType::HumanKey,
        $humanKey,
      );
    }
    if ($tenant !== '') {
      $selectors[] = new McpKillSelector(
        McpKillSelectorType::Tenant,
        $tenant,
      );
    }
    return $selectors;
  }

  /**
   * Batch id of a matching active kill-block, or empty.
   *
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Delivery keys.
   */
  private function matchingKillBatchId(array $selectors): string {
    if ($selectors === [] || !$this->database->schema()->tableExists(McpKillSwitch::TABLE)) {
      return '';
    }
    $hashes = [];
    foreach ($selectors as $selector) {
      $hashes[] = $selector->hash();
    }
    $row = $this->database->select(McpKillSwitch::TABLE, 'k')
      ->fields('k', ['batch_id'])
      ->condition('selector_hash', $hashes, 'IN')
      ->condition('status', [
        'killed',
        'kill_pending',
        'unkill_pending',
      ], 'IN')
      ->range(0, 1)
      ->execute()
      ?->fetchAssoc();
    return is_array($row) ? (string) $row['batch_id'] : '';
  }

  /**
   * Principal keys from the sealed or carried context.
   *
   * @return array{0: string, 1: string, 2: string}
   *   principalKey, humanKey, tenant.
   */
  private function currentPrincipalKeys(): array {
    $ctx = $this->holder->get();
    $carried = $this->holder->carriedPrincipal();
    $principalKey = '';
    $humanKey = '';
    $tenant = '';
    if ($ctx !== NULL) {
      try {
        $keys = McpPrincipalKey::fromClaims($ctx->keyClaims());
        $principalKey = $keys['principalKey'];
        $humanKey = $keys['humanKey'];
      }
      catch (McpPrincipalKeyException) {
      }
      $tenant = $ctx->tenant();
    }
    if ($carried !== NULL) {
      if ($principalKey === '') {
        $principalKey = $carried->principalKey;
      }
      if ($humanKey === '') {
        $humanKey = $carried->humanKey;
      }
      if ($tenant === '') {
        $tenant = $carried->tenant;
      }
    }
    return [$principalKey, $humanKey, $tenant];
  }

  /**
   * One HMAC audit row for hold, release, or discard.
   *
   * @param string $operation
   *   Audit operation name.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $operator
   *   Acting operator.
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Scope selectors, when known.
   * @param list<int> $itemIds
   *   Delivery ids.
   * @param string $batchId
   *   Kill batch or correlation id.
   */
  private function auditSideEffect(
    string $operation,
    McpOperatorIdentity $operator,
    array $selectors,
    array $itemIds,
    string $batchId,
  ): void {
    if ($this->weakened(self::WEAKEN_SKIP_AUDIT)) {
      return;
    }
    $scope = [];
    foreach ($selectors as $selector) {
      $scope[] = $selector->type->value . ':' . $selector->key;
    }
    if ($scope === [] && $itemIds !== []) {
      $scope[] = 'delivery:' . implode(',', $itemIds);
    }
    $this->auditLogger->logAlways($operation, [
      'actor' => $operator->storageId(),
      'scope' => implode(',', $scope),
      'target_selector' => implode(',', $scope),
      'timestamp' => (string) $this->time->getRequestTime(),
      'batch_id' => $batchId,
      'correlation_id' => $batchId !== '' ? $batchId : implode(',', $itemIds),
      'item_ids' => implode(',', $itemIds),
    ]);
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  private function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

}
