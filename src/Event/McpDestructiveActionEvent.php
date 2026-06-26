<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Event;

use Drupal\Core\Session\AccountInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched before a governed destructive action on a non-entity target.
 *
 * The entity-bound McpDestructiveOpEvent only describes operations on a single
 * EntityInterface (e.g. bulk delete). Config and admin operations such as
 * config_import, module_disable, or a break-glass role grant have no entity, so
 * this sibling event carries a free-form target descriptor (type + id) instead.
 *
 * Optional subscribers — such as the mcp_sentinel_approval submodule — may veto
 * the action, in which case the dispatching tool/command records it as queued
 * for approval and does NOT perform the action. When no subscriber vetoes the
 * event is a no-op and the action proceeds, keeping the base paths decoupled
 * from any approval workflow.
 */
final class McpDestructiveActionEvent extends Event {

  /**
   * The event name used for dispatch and subscription.
   */
  public const string NAME = 'mcp_sentinel.destructive_action';

  /**
   * The veto reason, or NULL when the action has not been vetoed.
   */
  private ?string $vetoReason = NULL;

  /**
   * Constructs an McpDestructiveActionEvent.
   *
   * @param string $targetType
   *   The target kind (e.g. 'config', 'module', 'user').
   * @param string $targetId
   *   The target identifier (e.g. a config name, module name, or uid).
   * @param string $operation
   *   The operation identifier (e.g. 'config_import', 'module_disable',
   *   'grant_mcp_admin').
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account performing the action.
   * @param array $payload
   *   Optional operation payload retained for the approval record / replay.
   */
  public function __construct(
    private readonly string $targetType,
    private readonly string $targetId,
    private readonly string $operation,
    private readonly AccountInterface $account,
    private readonly array $payload = [],
  ) {}

  /**
   * Gets the target kind.
   *
   * @return string
   *   The target type (e.g. 'config').
   */
  public function getTargetType(): string {
    return $this->targetType;
  }

  /**
   * Gets the target identifier.
   *
   * @return string
   *   The target id (e.g. a config name).
   */
  public function getTargetId(): string {
    return $this->targetId;
  }

  /**
   * Gets the operation identifier.
   *
   * @return string
   *   The operation (e.g. 'config_import').
   */
  public function getOperation(): string {
    return $this->operation;
  }

  /**
   * Gets the account performing the action.
   *
   * @return \Drupal\Core\Session\AccountInterface
   *   The acting account.
   */
  public function getAccount(): AccountInterface {
    return $this->account;
  }

  /**
   * Gets the operation payload.
   *
   * @return array
   *   The payload retained for the approval record / replay.
   */
  public function getPayload(): array {
    return $this->payload;
  }

  /**
   * Vetoes the action with a human-readable reason.
   *
   * @param string $reason
   *   Why the action was vetoed (shown to the caller, e.g. "Queued for
   *   approval (request #5).").
   */
  public function veto(string $reason): void {
    $this->vetoReason = $reason;
  }

  /**
   * Whether the action has been vetoed by a subscriber.
   *
   * @return bool
   *   TRUE if vetoed.
   */
  public function isVetoed(): bool {
    return $this->vetoReason !== NULL;
  }

  /**
   * Gets the veto reason, or NULL when not vetoed.
   *
   * @return string|null
   *   The veto reason.
   */
  public function getVetoReason(): ?string {
    return $this->vetoReason;
  }

}
