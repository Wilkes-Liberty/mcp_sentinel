<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\EventSubscriber;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\mcp_sentinel_approval\Service\McpApprovalGate;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Queues governed non-entity destructive actions for human approval.
 *
 * The entity-bound McpDestructiveOpSubscriber handles operations on a single
 * entity (e.g. bulk delete). This sibling handles target-descriptor actions
 * (config_import, module_disable, grant_mcp_admin) with no entity. When the
 * approval gate requires approval for the operation, it creates a pending
 * mcp_approval_request — recording the target kind/id as the synthetic
 * entity_type/entity_id — and vetoes the action so it does NOT execute now.
 */
final class McpDestructiveActionSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an McpDestructiveActionSubscriber.
   *
   * @param \Drupal\mcp_sentinel_approval\Service\McpApprovalGate $gate
   *   The approval gate.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   *   The mcp_sentinel logger channel.
   */
  public function __construct(
    private readonly McpApprovalGate $gate,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly LoggerChannelInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      McpDestructiveActionEvent::NAME => 'onDestructiveAction',
    ];
  }

  /**
   * Queues a non-entity destructive action for approval and vetoes execution.
   *
   * @param \Drupal\mcp_sentinel\Event\McpDestructiveActionEvent $event
   *   The destructive action event.
   */
  public function onDestructiveAction(McpDestructiveActionEvent $event): void {
    if (!$this->gate->requiresApproval($event->getOperation())) {
      return;
    }

    $payload = [
      'target_type' => $event->getTargetType(),
      'target_id'   => $event->getTargetId(),
      'operation'   => $event->getOperation(),
    ] + $event->getPayload();

    try {
      $storage = $this->entityTypeManager->getStorage('mcp_approval_request');
      $request = $storage->create([
        'requested_by' => (int) $event->getAccount()->id(),
        'operation'    => $event->getOperation(),
        // Non-entity targets: record the descriptor in entity_type/entity_id
        // columns so the request renders and the executor can replay it.
        'entity_type'  => $event->getTargetType(),
        'entity_id'    => $event->getTargetId(),
        'payload'      => (string) json_encode($payload),
        'status'       => McpApprovalRequestInterface::STATUS_PENDING,
      ]);
      $request->save();
    }
    catch (\Throwable $e) {
      // If we cannot record the request, veto anyway: a gated action must never
      // silently proceed because bookkeeping failed.
      $this->logger->error(
        'Failed to create approval request for @op on @type @id: @msg',
        [
          '@op'   => $event->getOperation(),
          '@type' => $event->getTargetType(),
          '@id'   => $event->getTargetId(),
          '@msg'  => $e->getMessage(),
        ],
      );
      $event->veto('Queued for approval (request could not be recorded; action blocked).');
      return;
    }

    $event->veto(sprintf('Queued for approval (request #%s).', (string) $request->id()));
  }

}
