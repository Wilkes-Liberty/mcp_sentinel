<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;

/**
 * Executes approve/deny decisions on MCP approval requests.
 *
 * On approve, the stored destructive operation is replayed (currently delete):
 * the target entity is reloaded, re-access-checked for the approver, and
 * deleted if it still exists. The decision is recorded on the request and an
 * audit row is written via the base audit logger. On deny, the request is
 * marked denied and the decision audited without touching the target.
 */
final class McpApprovalExecutor {

  /**
   * Constructs an McpApprovalExecutor.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The base audit logger.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user (the approver).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly McpAuditLogger $auditLogger,
    private readonly AccountProxyInterface $currentUser,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Approves a request and replays the stored operation.
   *
   * Status semantics (Fix 3): the request is only recorded as approved when the
   * operation either executed or is genuinely unexecutable (target already
   * gone, unknown/uninstalled entity type, or a UUID mismatch indicating the
   * id was reused by a different entity). A recoverable block — the approver
   * lacking delete access on a still-present target — leaves the request
   * PENDING and returns an error so an authorized admin can retry; nothing is
   * deleted and no "approved" audit row is written.
   *
   * @param \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request
   *   The approval request to approve.
   *
   * @return array{executed: bool, error: bool, message: string}
   *   'executed' is TRUE only when the target was deleted. 'error' is TRUE when
   *   the request could not be decided and remains pending (caller should
   *   surface the message and allow a retry). 'message' is a human summary.
   *
   * @throws \LogicException
   *   When the request is not pending (already approved or denied), preventing
   *   a replayed/double decision.
   */
  public function approve(McpApprovalRequestInterface $request): array {
    if (!$request->isPending()) {
      throw new \LogicException(sprintf('Cannot decide request #%s: status is already "%s".', $request->id(), $request->getStatus()));
    }

    $uid = (int) $this->currentUser->id();
    $now = $this->time->getRequestTime();
    $entity_type = $request->getTargetEntityTypeId();
    $entity_id = $request->getTargetEntityId();

    $executed = FALSE;
    $reason = NULL;
    $message = '';

    if ($request->getOperation() === 'delete') {
      // Guard against an invalid or uninstalled entity type (Fix 2): calling
      // getStorage() on an unknown type throws PluginNotFoundException. Treat
      // it as a non-executable target rather than a fatal that strands the
      // request pending. Mirrors the hasDefinition() guard in the bulk tool.
      if (!$this->entityTypeManager->hasDefinition($entity_type)) {
        $reason = sprintf('unknown_entity_type:%s', $entity_type);
        $message = sprintf('Unknown entity type "%s"; target cannot be loaded. Request marked approved but not executed.', $entity_type);
      }
      else {
        $entity = $this->entityTypeManager->getStorage($entity_type)->load($entity_id);
        if ($entity === NULL) {
          $reason = 'target_already_deleted';
          $message = 'Target already deleted; request marked approved.';
        }
        elseif (($expected_uuid = (string) ($request->getPayload()['entity_uuid'] ?? '')) !== '' && $expected_uuid !== (string) $entity->uuid()) {
          // Fix 4: the stored id now resolves to a DIFFERENT entity (the
          // original was deleted and the auto-increment id was reused). Do not
          // delete the wrong entity; block and record the mismatch.
          $reason = 'uuid_mismatch';
          $message = 'Target identity changed (UUID mismatch); the original entity no longer exists. Request marked approved but not executed.';
        }
        elseif (!$entity->access('delete', $this->currentUser)) {
          // Fix 3 (option a): recoverable block — leave PENDING and surface an
          // error so an authorized approver can retry. Do not record approved.
          return [
            'executed' => FALSE,
            'error'    => TRUE,
            'message'  => 'Approver lacks delete access on the target; request left pending. An authorized approver can retry.',
          ];
        }
        else {
          $entity->delete();
          $executed = TRUE;
          $message = 'Target deleted.';
        }
      }
    }
    else {
      $reason = sprintf('unsupported_operation:%s', $request->getOperation());
      $message = sprintf('Unsupported operation "%s"; request marked approved but not executed.', $request->getOperation());
    }

    $request
      ->setStatus(McpApprovalRequestInterface::STATUS_APPROVED)
      ->setDecision($uid, $now)
      ->save();

    $metadata = [
      'entity_type' => $entity_type,
      'id'          => $entity_id,
      'decision'    => 'approved',
      'request_id'  => (int) $request->id(),
      'operation'   => $request->getOperation(),
      'executed'    => $executed,
      'decided_by'  => $uid,
    ];
    if (!$executed && $reason !== NULL) {
      $metadata['reason'] = $reason;
      $metadata['note'] = $message;
    }
    $this->auditLogger->log('approval_decision', $metadata);

    return ['executed' => $executed, 'error' => FALSE, 'message' => $message];
  }

  /**
   * Denies a request without executing the stored operation.
   *
   * @param \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request
   *   The approval request to deny.
   *
   * @throws \LogicException
   *   When the request is not pending (already approved or denied).
   */
  public function deny(McpApprovalRequestInterface $request): void {
    if (!$request->isPending()) {
      throw new \LogicException(sprintf('Cannot decide request #%s: status is already "%s".', $request->id(), $request->getStatus()));
    }

    $uid = (int) $this->currentUser->id();
    $request
      ->setStatus(McpApprovalRequestInterface::STATUS_DENIED)
      ->setDecision($uid, $this->time->getRequestTime())
      ->save();

    $this->auditLogger->log('approval_decision', [
      'entity_type' => $request->getTargetEntityTypeId(),
      'id'          => $request->getTargetEntityId(),
      'decision'    => 'denied',
      'request_id'  => (int) $request->id(),
      'operation'   => $request->getOperation(),
      'executed'    => FALSE,
      'decided_by'  => $uid,
    ]);
  }

}
