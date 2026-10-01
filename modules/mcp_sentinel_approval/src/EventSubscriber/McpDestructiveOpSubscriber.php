<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\EventSubscriber;

use Drupal\Core\Entity\RevisionableInterface;
use Drupal\mcp_sentinel\Event\McpDestructiveOpEvent;
use Drupal\mcp_sentinel\Service\McpActionManifestSealer;
use Drupal\mcp_sentinel\Service\McpEvidenceGuard;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel_approval\Service\McpApprovalGate;
use Drupal\mcp_sentinel_approval\Service\McpApprovalRequestRecorder;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Queues governed destructive operations for human approval.
 *
 * When the approval gate requires approval for the operation, this subscriber
 * creates a pending mcp_approval_request and vetoes the destructive event, so
 * the base module records the entity as queued and does NOT delete it.
 */
final class McpDestructiveOpSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an McpDestructiveOpSubscriber.
   *
   * @param \Drupal\mcp_sentinel_approval\Service\McpApprovalGate $gate
   *   The approval gate.
   * @param \Drupal\mcp_sentinel_approval\Service\McpApprovalRequestRecorder $recorder
   *   Writes the pending approval request.
   * @param \Drupal\mcp_sentinel\Service\McpActionManifestSealer $sealer
   *   Mints a sealed manifest when the signing key resolves. A NULL
   *   mint does not change who is gated.
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves the active profile for the policy digest.
   */
  public function __construct(
    private readonly McpApprovalGate $gate,
    private readonly McpApprovalRequestRecorder $recorder,
    private readonly McpActionManifestSealer $sealer,
    private readonly McpPolicyResolver $policyResolver,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      McpDestructiveOpEvent::NAME => 'onDestructiveOp',
    ];
  }

  /**
   * Queues a destructive operation for approval and vetoes execution.
   *
   * @param \Drupal\mcp_sentinel\Event\McpDestructiveOpEvent $event
   *   The destructive operation event.
   */
  public function onDestructiveOp(McpDestructiveOpEvent $event): void {
    if (!$this->gate->requiresApproval($event->getOperation())) {
      return;
    }

    $entity = $event->getEntity();
    // Bind the target by UUID as well as its int id so a later approval cannot
    // delete a different entity that reused the same auto-increment id after
    // the original was removed out-of-band. See McpApprovalExecutor::approve().
    $payload = [
      'entity_type' => $entity->getEntityTypeId(),
      'entity_id'   => (string) $entity->id(),
      'entity_uuid' => (string) $entity->uuid(),
      'label'       => (string) $entity->label(),
      'operation'   => $event->getOperation(),
    ];
    $revision = $entity instanceof RevisionableInterface
      ? (string) $entity->getRevisionId()
      : NULL;
    $manifest = $this->sealer->tryMint(
      $event->getAccount(),
      $event->getOperation(),
      [
        'type' => $entity->getEntityTypeId(),
        'id' => (string) $entity->id(),
        'uuid' => (string) $entity->uuid(),
        'revision' => $revision,
      ],
      $payload,
      McpEvidenceGuard::policyDigest(
        $this->policyResolver->resolve($event->getAccount()),
      ),
    );

    $request = $this->recorder->record(
      $event->getAccount(),
      $event->getOperation(),
      $entity->getEntityTypeId(),
      (string) $entity->id(),
      $payload,
      $manifest,
    );
    if ($request === NULL) {
      $event->veto(
        'Queued for approval (request could not be recorded; operation blocked).',
      );
      return;
    }

    $event->veto(sprintf(
      'Queued for approval (request #%s).',
      (string) $request->id(),
    ));
  }

}
