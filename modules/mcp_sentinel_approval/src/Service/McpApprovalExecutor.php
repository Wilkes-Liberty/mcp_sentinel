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
   * @param \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request
   *   The approval request to approve.
   *
   * @return array{executed: bool, message: string}
   *   'executed' is TRUE when the target was deleted; FALSE when the target was
   *   already gone or access was denied. 'message' is a human summary.
   */
  public function approve(McpApprovalRequestInterface $request): array {
    $uid = (int) $this->currentUser->id();
    $now = $this->time->getRequestTime();
    $entity_type = $request->getTargetEntityTypeId();
    $entity_id = $request->getTargetEntityId();

    $executed = FALSE;
    $message = '';

    if ($request->getOperation() === 'delete') {
      $entity = $this->entityTypeManager->getStorage($entity_type)->load($entity_id);
      if ($entity === NULL) {
        $message = 'Target already deleted; request marked approved.';
      }
      elseif (!$entity->access('delete', $this->currentUser)) {
        $message = 'Approver lacks delete access on the target; request marked approved but not executed.';
      }
      else {
        $entity->delete();
        $executed = TRUE;
        $message = 'Target deleted.';
      }
    }
    else {
      $message = sprintf('Unsupported operation "%s"; request marked approved but not executed.', $request->getOperation());
    }

    $request
      ->setStatus(McpApprovalRequestInterface::STATUS_APPROVED)
      ->setDecision($uid, $now)
      ->save();

    $this->auditLogger->log('approval_decision', [
      'entity_type' => $entity_type,
      'id'          => $entity_id,
      'decision'    => 'approved',
      'request_id'  => (int) $request->id(),
      'operation'   => $request->getOperation(),
      'executed'    => $executed,
    ]);

    return ['executed' => $executed, 'message' => $message];
  }

  /**
   * Denies a request without executing the stored operation.
   *
   * @param \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request
   *   The approval request to deny.
   */
  public function deny(McpApprovalRequestInterface $request): void {
    $request
      ->setStatus(McpApprovalRequestInterface::STATUS_DENIED)
      ->setDecision((int) $this->currentUser->id(), $this->time->getRequestTime())
      ->save();

    $this->auditLogger->log('approval_decision', [
      'entity_type' => $request->getTargetEntityTypeId(),
      'id'          => $request->getTargetEntityId(),
      'decision'    => 'denied',
      'request_id'  => (int) $request->id(),
      'operation'   => $request->getOperation(),
      'executed'    => FALSE,
    ]);
  }

}
