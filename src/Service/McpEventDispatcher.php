<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\mcp_sentinel\Event\McpEntityEvent;
use Drupal\mcp_sentinel\McpWebhookEvents;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Dispatches Drupal events and queues HMAC-signed HTTPS webhooks for changes.
 *
 * Each governed entity change fans out two ways: a synchronous in-process
 * McpEntityEvent (for other modules to subscribe to) and, when any webhook
 * endpoint is configured, an asynchronous webhook enqueue for external systems.
 *
 * Webhook delivery is reliable: each configured endpoint that matches the
 * event records a pending row in mcp_sentinel_webhook_delivery and is queued
 * for the McpWebhookWorker, which performs HTTPS POST with HMAC-SHA256 signing,
 * retry/backoff, and an SSRF guard. The signing secret is resolved from a Key
 * entity per endpoint so it never lives in exported configuration.
 *
 * The payload "timestamp" is the event time and stays the same on every
 * delivery attempt. Each attempt also carries X-MCP-Timestamp (send time),
 * X-MCP-Delivery (row id) and X-MCP-Signature-256, an HMAC over
 * "{timestamp}.{body}"; see the README "Reliable webhooks" section.
 *
 * Verify X-MCP-Signature-256 against "{X-MCP-Timestamp}.{raw body}".
 * Also reject X-MCP-Timestamp outside your allowed clock skew; see
 * README "Reliable webhooks" step 3 (the snippet uses 300 seconds):
 *   $timestamp = $request->headers->get('X-MCP-Timestamp', '');
 *   $expected = 'sha256=' . hash_hmac(
 *     'sha256',
 *     $timestamp . '.' . $body,
 *     $secret,
 *   );
 *   $valid = hash_equals(
 *     $expected,
 *     $request->headers->get('X-MCP-Signature-256', ''),
 *   )
 *     && preg_match('/^[0-9]+$/', $timestamp) === 1
 *     && abs(time() - (int) $timestamp) <= 300;
 *
 * X-MCP-Signature is the body-only legacy header. Do not apply that
 * verify to X-MCP-Signature-256.
 */
class McpEventDispatcher {

  /**
   * Constructs an McpEventDispatcher service.
   *
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $eventDispatcher
   *   The event dispatcher (fires the in-process McpEntityEvent).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (reads the configured webhook endpoints).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service (stamps the outbound webhook payload).
   * @param \Drupal\mcp_sentinel\Service\McpWebhookQueueManager $webhookQueueManager
   *   The webhook queue manager that records and enqueues each delivery.
   */
  public function __construct(
    private readonly EventDispatcherInterface $eventDispatcher,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly McpWebhookQueueManager $webhookQueueManager,
  ) {}

  /**
   * Dispatches an MCP entity event and queues webhooks for matching endpoints.
   *
   * Unknown names and non-entity names return without firing. An entity
   * name always fires the in-process event; the webhook enqueue only
   * runs when at least one endpoint is configured (the queue manager
   * applies the per-event and enabled-flag filtering). The payload
   * carries a stable, serializable snapshot of the entity rather than
   * the entity object, so the queued item stays valid even if the
   * entity later changes or is deleted.
   *
   * @param string $eventName
   *   An entity MCP event identifier (see McpWebhookEvents::ENTITY).
   *   Unknown names and mcp.anomaly.alert return without firing or
   *   queuing and write a webhook_event_refused audit row.
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity the event concerns.
   */
  public function dispatch(string $eventName, EntityInterface $entity): void {
    // dispatch() builds an entity payload. Only entity names may fire
    // here; the alert name is live for enqueueForEvent() but not for
    // this path. A refusal is audited and never queues.
    if (!McpWebhookEvents::isEntityEvent($eventName)) {
      $this->webhookQueueManager->auditRefusedEventName(
        $eventName,
        McpWebhookQueueManager::SURFACE_DISPATCH,
      );
      return;
    }
    $this->eventDispatcher->dispatch(new McpEntityEvent($entity, $eventName), $eventName);

    $config = $this->configFactory->get('mcp_sentinel.settings');
    $endpoints = $config->get('webhook_endpoints') ?? [];
    if ($endpoints) {
      $this->webhookQueueManager->enqueueForEvent($eventName, [
        'event'       => $eventName,
        'entity_type' => $entity->getEntityTypeId(),
        'bundle'      => $entity->bundle(),
        'id'          => $entity->id(),
        'uuid'        => $entity->uuid(),
        'label'       => (string) $entity->label(),
        'timestamp'   => $this->time->getRequestTime(),
      ]);
    }
  }

}
