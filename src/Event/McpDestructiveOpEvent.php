<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Event;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Session\AccountInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched before a governed destructive operation executes on an entity.
 *
 * The base module dispatches this immediately before performing a destructive
 * operation (currently bulk delete) on a single entity, after all access,
 * policy, and lock checks have passed. Optional subscribers — such as the
 * mcp_sentinel_approval submodule — may veto the operation, in which case the
 * base module records the entity as queued and does NOT perform the operation.
 *
 * When no subscriber vetoes (e.g. the submodule is absent or approval is not
 * required for the operation), the event is a no-op and the destructive
 * operation proceeds unchanged. This keeps the base module fully decoupled from
 * any approval workflow.
 */
final class McpDestructiveOpEvent extends Event {

  /**
   * The event name used for dispatch and subscription.
   */
  public const string NAME = 'mcp_sentinel.destructive_op';

  /**
   * The veto reason, or NULL when the operation has not been vetoed.
   */
  private ?string $vetoReason = NULL;

  /**
   * Constructs an McpDestructiveOpEvent.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity targeted by the destructive operation.
   * @param string $operation
   *   The operation identifier (e.g. 'delete').
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account performing the operation.
   */
  public function __construct(
    private readonly EntityInterface $entity,
    private readonly string $operation,
    private readonly AccountInterface $account,
  ) {}

  /**
   * Gets the entity targeted by the destructive operation.
   *
   * @return \Drupal\Core\Entity\EntityInterface
   *   The target entity.
   */
  public function getEntity(): EntityInterface {
    return $this->entity;
  }

  /**
   * Gets the operation identifier.
   *
   * @return string
   *   The operation (e.g. 'delete').
   */
  public function getOperation(): string {
    return $this->operation;
  }

  /**
   * Gets the account performing the operation.
   *
   * @return \Drupal\Core\Session\AccountInterface
   *   The acting account.
   */
  public function getAccount(): AccountInterface {
    return $this->account;
  }

  /**
   * Vetoes the destructive operation with a human-readable reason.
   *
   * @param string $reason
   *   Why the operation was vetoed (shown to the caller, e.g. "Queued for
   *   approval (request #5).").
   */
  public function veto(string $reason): void {
    $this->vetoReason = $reason;
  }

  /**
   * Whether the operation has been vetoed by a subscriber.
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
