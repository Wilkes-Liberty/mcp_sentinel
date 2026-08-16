<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\EventSubscriber;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Event\McpDestructiveOpEvent;
use Drupal\mcp_sentinel\Service\McpActionManifestSealer;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\mcp_sentinel_approval\Service\McpApprovalGate;
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
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   *   The mcp_sentinel logger channel.
   * @param \Drupal\mcp_sentinel\Service\McpActionManifestSealer $sealer
   *   Mints a sealed manifest when the signing key resolves. A NULL
   *   mint does not change who is gated.
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves the active profile for the policy digest.
   */
  public function __construct(
    private readonly McpApprovalGate $gate,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerChannelInterface $logger,
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
      $this->policyDigest($event->getAccount()),
    );

    try {
      $storage = $this->entityTypeManager->getStorage('mcp_approval_request');
      $request = $storage->create([
        'requested_by' => (int) $event->getAccount()->id(),
        'operation'    => $event->getOperation(),
        'entity_type'  => $entity->getEntityTypeId(),
        'entity_id'    => (string) $entity->id(),
        'payload'      => (string) json_encode($payload),
        'status'       => McpApprovalRequestInterface::STATUS_PENDING,
        'manifest'     => $manifest?->toJson() ?? '',
      ]);
      $request->save();
    }
    catch (\Throwable $e) {
      // If we cannot record the request, veto anyway: a destructive op gated
      // for approval must never silently proceed because bookkeeping failed.
      $this->logger->error(
        'Failed to create approval request for @op on @type @id: @msg',
        [
          '@op'   => $event->getOperation(),
          '@type' => $entity->getEntityTypeId(),
          '@id'   => (string) $entity->id(),
          '@msg'  => $e->getMessage(),
        ],
      );
      $event->veto('Queued for approval (request could not be recorded; operation blocked).');
      return;
    }

    $event->veto(sprintf('Queued for approval (request #%s).', (string) $request->id()));
  }

  /**
   * Policy digest for the actor, or NULL when no profile resolved.
   */
  private function policyDigest(AccountInterface $account): ?string {
    $profile = $this->policyResolver->resolve($account);
    if ($profile === NULL) {
      return NULL;
    }
    return 'sha256:' . hash('sha256', (string) json_encode($profile->toArray()));
  }

}
