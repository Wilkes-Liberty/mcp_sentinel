<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Session\AccountProxyInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Logs MCP operations to the mcp_sentinel_audit_log table.
 *
 * Governed requests are identified by the McpPolicyResolver (the validated
 * OAuth agent channel). Each entry is attributed to the authenticated account —
 * the acting admin (the OAuth subject) on the agent channel.
 */
class McpAuditLogger {

  /**
   * Constructs an McpAuditLogger.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack (used for IP address and User-Agent in log entries).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly RequestStack $requestStack,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Logs an MCP operation.
   *
   * @param string $operation
   *   A short operation identifier (e.g. 'entity_save', 'entity_delete').
   * @param array $metadata
   *   Optional metadata. Recognised keys: entity_type, bundle, id, label.
   *   Remaining keys are JSON-encoded into the metadata column.
   */
  public function log(string $operation, array $metadata = []): void {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    if (!$config->get('audit_enabled')) {
      return;
    }
    if (str_starts_with($operation, 'entity_read') && !$config->get('audit_log_reads')) {
      return;
    }
    $request = $this->requestStack->getCurrentRequest();
    $this->database->insert('mcp_sentinel_audit_log')
      ->fields([
        'timestamp'    => $this->time->getRequestTime(),
        'uid'          => $this->currentUser->id(),
        'operation'    => substr($operation, 0, 64),
        'entity_type'  => $metadata['entity_type'] ?? NULL,
        'bundle'       => $metadata['bundle'] ?? NULL,
        'entity_id'    => (string) ($metadata['id'] ?? ''),
        'entity_label' => isset($metadata['label'])
          ? substr($metadata['label'], 0, 255)
          : NULL,
        'ip_address'   => $request?->getClientIp(),
        'user_agent'   => $request
          ? substr($request->headers->get('User-Agent', ''), 0, 512)
          : NULL,
        'metadata'     => json_encode(
          array_diff_key($metadata, array_flip(['entity_type', 'bundle', 'id', 'label']))
        ),
      ])
      ->execute();
  }

  /**
   * Deletes log entries older than the configured retention period.
   *
   * @return int
   *   Number of rows deleted.
   */
  public function pruneOldEntries(): int {
    $days = (int) $this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('audit_retention_days');
    if ($days <= 0) {
      return 0;
    }
    $cutoff = $this->time->getRequestTime() - ($days * 86400);
    return (int) $this->database->delete('mcp_sentinel_audit_log')
      ->condition('timestamp', $cutoff, '<')
      ->execute();
  }

}
