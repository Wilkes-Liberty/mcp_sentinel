<?php

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\mcp_sentinel\Event\McpEntityEvent;
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
 * Verify signature:
 *   hash_equals('sha256=' . hash_hmac('sha256', $body, $secret), $header)
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
   * The in-process event always fires; the webhook enqueue only runs when at
   * least one endpoint is configured (the queue manager applies the per-event
   * and enabled-flag filtering). The payload carries a stable, serializable
   * snapshot of the entity rather than the entity object, so the queued item
   * stays valid even if the entity later changes or is deleted.
   *
   * @param string $eventName
   *   The MCP event identifier (e.g. mcp.entity.presave).
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity the event concerns.
   */
  public function dispatch(string $eventName, EntityInterface $entity): void {
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
