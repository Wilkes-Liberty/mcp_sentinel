<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Value\McpActionManifest;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;

/**
 * Writes one pending approval request for a gated destructive event.
 *
 * Shared by the entity-bound and non-entity subscribers so the queue
 * insert, fail-closed log, and stored field set cannot drift. Callers
 * still veto their own event type; this class does not merge them.
 */
final class McpApprovalRequestRecorder {

  /**
   * Constructs an McpApprovalRequestRecorder.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   *   The mcp_sentinel logger channel.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerChannelInterface $logger,
  ) {}

  /**
   * Records a pending approval request.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The requester.
   * @param string $operation
   *   The gated operation identifier.
   * @param string $entityType
   *   The target entity type, or a synthetic kind for non-entity actions.
   * @param string $entityId
   *   The target entity id, or a synthetic id for non-entity actions.
   * @param array $payload
   *   The payload stored for display (already redacted when required).
   * @param \Drupal\mcp_sentinel\Value\McpActionManifest|null $manifest
   *   The sealed manifest, or NULL when the signing key did not resolve.
   *
   * @return \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface|null
   *   The saved request, or NULL when recording failed (already logged).
   *   A gated caller must still veto; bookkeeping failure must not proceed.
   */
  public function record(
    AccountInterface $account,
    string $operation,
    string $entityType,
    string $entityId,
    array $payload,
    ?McpActionManifest $manifest,
  ): ?McpApprovalRequestInterface {
    try {
      $storage = $this->entityTypeManager->getStorage('mcp_approval_request');
      $request = $storage->create([
        'requested_by' => (int) $account->id(),
        'operation'    => $operation,
        'entity_type'  => $entityType,
        'entity_id'    => $entityId,
        'payload'      => (string) json_encode($payload),
        'status'       => McpApprovalRequestInterface::STATUS_PENDING,
        'manifest'     => $manifest?->toJson() ?? '',
      ]);
      $request->save();
    }
    catch (\Throwable $e) {
      // If we cannot record the request, the caller still vetoes: a gated
      // op must never silently proceed because bookkeeping failed.
      // Not the message: a storage exception repeats the query arguments,
      // and those are the payload and the manifest.
      $this->logger->error(
        'Failed to create approval request for @op on @type @id: @class at @file:@line.',
        [
          '@op'    => $operation,
          '@type'  => $entityType,
          '@id'    => $entityId,
          '@class' => get_class($e),
          '@file'  => basename($e->getFile()),
          '@line'  => $e->getLine(),
        ],
      );
      return NULL;
    }

    return $request instanceof McpApprovalRequestInterface ? $request : NULL;
  }

}
