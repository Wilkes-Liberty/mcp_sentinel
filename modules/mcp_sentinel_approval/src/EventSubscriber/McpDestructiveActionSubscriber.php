<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\EventSubscriber;

use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drupal\mcp_sentinel\Service\McpActionManifestSealer;
use Drupal\mcp_sentinel\Service\McpConfigSecretRedactor;
use Drupal\mcp_sentinel\Service\McpEvidenceGuard;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel_approval\Service\McpApprovalGate;
use Drupal\mcp_sentinel_approval\Service\McpApprovalRequestRecorder;
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
   * @param \Drupal\mcp_sentinel_approval\Service\McpApprovalRequestRecorder $recorder
   *   Writes the pending approval request.
   * @param \Drupal\mcp_sentinel\Service\McpActionManifestSealer $sealer
   *   Mints a sealed manifest when the signing key resolves.
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   Resolves the active profile for the policy digest.
   * @param \Drupal\mcp_sentinel\Service\McpConfigSecretRedactor|null $configSecrets
   *   Withholds secrets from the stored display payload of a config change.
   */
  public function __construct(
    private readonly McpApprovalGate $gate,
    private readonly McpApprovalRequestRecorder $recorder,
    private readonly McpActionManifestSealer $sealer,
    private readonly McpPolicyResolver $policyResolver,
    private readonly ?McpConfigSecretRedactor $configSecrets = NULL,
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
    $manifest = $this->sealer->tryMint(
      $event->getAccount(),
      $event->getOperation(),
      [
        'type' => $event->getTargetType(),
        'id' => $event->getTargetId(),
      ],
      $payload,
      McpEvidenceGuard::policyDigest(
        $this->policyResolver->resolve($event->getAccount()),
      ),
    );

    $request = $this->recorder->record(
      $event->getAccount(),
      $event->getOperation(),
      $event->getTargetType(),
      $event->getTargetId(),
      $this->displayPayload($event, $payload),
      $manifest,
    );
    if ($request === NULL) {
      $event->veto(
        'Queued for approval (request could not be recorded; action blocked).',
      );
      return;
    }

    $event->veto(sprintf(
      'Queued for approval (request #%s).',
      (string) $request->id(),
    ));
  }

  /**
   * The payload as stored for display: config values with secrets withheld.
   */
  private function displayPayload(McpDestructiveActionEvent $event, array $payload): array {
    if ($event->getTargetType() !== 'config' || !is_array($payload['data'] ?? NULL)) {
      return $payload;
    }
    $secrets = $this->configSecrets ?? new McpConfigSecretRedactor();
    $redacted = $this->policyResolver->resolve($event->getAccount())?->getRedactedFields() ?? [];
    $payload['data'] = $secrets->redactForName($event->getTargetId(), $payload['data'], $redacted);
    return $payload;
  }

}
