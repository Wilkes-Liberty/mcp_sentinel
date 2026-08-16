<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\IntegrityConstraintViolationException;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpDecisionReason;
use Drupal\mcp_sentinel\Service\McpActionManifestSealer;
use Drupal\mcp_sentinel\Value\McpActionManifest;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;

/**
 * Binds an approval decision to exactly one sealed action manifest.
 *
 * Slice 3 of #3616538. Fail-closed: a missing, invalid, expired, stale
 * or already-consumed manifest cannot execute. Recoverable refusals
 * (the approver is the requester) leave the request pending.
 */
final class McpManifestBinder {

  /**
   * Constructs the binder.
   *
   * @param \Drupal\mcp_sentinel\Service\McpActionManifestSealer $sealer
   *   Opens and verifies stored seals.
   * @param \Drupal\Core\Database\Connection $database
   *   Stores consumed idempotency keys.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Clock for expiry and consume stamps.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The deciding account.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Used to compare the live target revision.
   */
  public function __construct(
    private readonly McpActionManifestSealer $sealer,
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly AccountProxyInterface $currentUser,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Validates the request's sealed manifest for an approve attempt.
   *
   * @param \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request
   *   The pending request.
   *
   * @return array<string, mixed>
   *   ok when the manifest may be consumed and executed. error when the
   *   request should stay pending (another actor can retry).
   */
  public function validate(McpApprovalRequestInterface $request): array {
    $uid = (int) $this->currentUser->id();
    if ($uid === $request->getRequestedById()) {
      return $this->fail(TRUE, McpDecisionReason::SelfApproval, 'The requester cannot approve their own request.');
    }
    if (!$this->currentUser->hasPermission('approve mcp sentinel operations')) {
      return $this->fail(TRUE, McpDecisionReason::ApproverUnauthorized, 'The current account cannot approve MCP Sentinel operations.');
    }

    $raw = $request->getSealedManifest();
    if ($raw === '') {
      return $this->fail(FALSE, McpDecisionReason::ManifestMissing, 'This request has no sealed action manifest and cannot execute.');
    }
    $manifest = $this->sealer->open($raw);
    if ($manifest === NULL) {
      return $this->fail(FALSE, McpDecisionReason::ManifestInvalid, 'The stored action manifest is not valid for the current signing key.');
    }
    if ($this->time->getRequestTime() > $manifest->expires()) {
      return $this->fail(FALSE, McpDecisionReason::ManifestExpired, 'The sealed action manifest has expired.');
    }
    if ($manifest->operation() !== $request->getOperation()) {
      return $this->fail(FALSE, McpDecisionReason::ManifestInvalid, 'The sealed manifest does not match the request operation.');
    }

    $stale = $this->staleTarget($manifest);
    if ($stale !== NULL) {
      return $stale;
    }

    return [
      'ok' => TRUE,
      'error' => FALSE,
      'reason' => NULL,
      'message' => '',
      'manifest' => $manifest,
    ];
  }

  /**
   * Consumes the idempotency key. FALSE when it was already used.
   */
  public function consume(McpActionManifest $manifest, int $requestId): bool {
    try {
      $this->database->insert('mcp_sentinel_manifest_used')
        ->fields([
          'idempotency_key' => $manifest->idempotencyKey(),
          'request_id' => $requestId,
          'used' => $this->time->getRequestTime(),
        ])
        ->execute();
      return TRUE;
    }
    catch (IntegrityConstraintViolationException) {
      return FALSE;
    }
  }

  /**
   * Compares the live target to the sealed revision/uuid when required.
   *
   * @return array<string, mixed>|null
   *   A failure result, or NULL when the target still matches.
   */
  private function staleTarget(McpActionManifest $manifest): ?array {
    $needed = $manifest->preconditions();
    if (!in_array('target_uuid', $needed, TRUE) && !in_array('target_revision', $needed, TRUE)) {
      return NULL;
    }
    $target = $manifest->target();
    if (!$this->entityTypeManager->hasDefinition($target['type'])) {
      return NULL;
    }
    $entity = $this->entityTypeManager->getStorage($target['type'])->load($target['id']);
    if ($entity === NULL) {
      return NULL;
    }
    if (in_array('target_uuid', $needed, TRUE) && $target['uuid'] !== NULL && $target['uuid'] !== (string) $entity->uuid()) {
      return $this->fail(FALSE, McpDecisionReason::TargetStale, 'The live target is not the entity the manifest sealed.');
    }
    if (in_array('target_revision', $needed, TRUE) && $entity instanceof RevisionableInterface && $target['revision'] !== NULL && $target['revision'] !== (string) $entity->getRevisionId()) {
      return $this->fail(FALSE, McpDecisionReason::TargetStale, 'The live target revision is not the revision the manifest sealed.');
    }
    return NULL;
  }

  /**
   * Builds a failure result.
   *
   * @return array<string, mixed>
   *   Failure payload.
   */
  private function fail(bool $pending, McpDecisionReason $reason, string $message): array {
    return [
      'ok' => FALSE,
      'error' => $pending,
      'reason' => $reason->value,
      'message' => $message,
      'manifest' => NULL,
    ];
  }

}
