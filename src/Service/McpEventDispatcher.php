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

  public function __construct(
    private readonly EventDispatcherInterface $eventDispatcher,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly McpWebhookQueueManager $webhookQueueManager,
  ) {}

  /**
   * Dispatch an MCP entity event and queue webhooks for matching endpoints.
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
