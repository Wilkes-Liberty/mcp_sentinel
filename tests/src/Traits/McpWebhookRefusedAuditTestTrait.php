<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;

/**
 * Shared helper for webhook_event_refused audit rows.
 */
trait McpWebhookRefusedAuditTestTrait {

  /**
   * Latest webhook_event_refused metadata, or fail if none.
   *
   * @return array<string, mixed>
   *   Decoded metadata.
   */
  protected function latestRefusedAudit(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['operation', 'metadata'])
      ->condition('l.operation', McpWebhookQueueManager::AUDIT_EVENT_REFUSED)
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse(
      $row,
      'A webhook_event_refused audit row must exist.',
    );
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
  }

}
