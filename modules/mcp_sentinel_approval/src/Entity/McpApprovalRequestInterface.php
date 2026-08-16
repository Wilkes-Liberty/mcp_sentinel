<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Entity;

use Drupal\Core\Entity\ContentEntityInterface;

/**
 * Defines the interface for an MCP approval request entity.
 */
interface McpApprovalRequestInterface extends ContentEntityInterface {

  /**
   * Status: awaiting a human decision.
   */
  public const string STATUS_PENDING = 'pending';

  /**
   * Status: approved and the operation executed (or attempted).
   */
  public const string STATUS_APPROVED = 'approved';

  /**
   * Status: denied; the operation will not run.
   */
  public const string STATUS_DENIED = 'denied';

  /**
   * Gets the requested operation identifier (e.g. 'delete').
   */
  public function getOperation(): string;

  /**
   * Gets the requester user id.
   */
  public function getRequestedById(): int;

  /**
   * Gets the target entity type id.
   */
  public function getTargetEntityTypeId(): string;

  /**
   * Gets the target entity id.
   */
  public function getTargetEntityId(): string;

  /**
   * Gets the decoded replay payload array.
   *
   * @return array
   *   The payload, or an empty array when none was stored.
   */
  public function getPayload(): array;

  /**
   * Gets the sealed action-manifest JSON, if one was minted.
   *
   * Empty on requests queued before slice 2, or when the signing key
   * could not resolve at mint time. Slice 3 is what starts refusing
   * an empty value.
   */
  public function getSealedManifest(): string;

  /**
   * Stores the sealed action-manifest JSON.
   *
   * @param string $manifest
   *   Sealed JSON from McpActionManifest::toJson().
   *
   * @return $this
   */
  public function setSealedManifest(string $manifest): static;

  /**
   * Gets the current status (pending/approved/denied).
   */
  public function getStatus(): string;

  /**
   * Sets the status.
   *
   * @param string $status
   *   One of the STATUS_* constants.
   *
   * @return $this
   */
  public function setStatus(string $status): static;

  /**
   * Whether the request is still pending a decision.
   */
  public function isPending(): bool;

  /**
   * Records the decision maker (uid) and decision timestamp.
   *
   * @param int $uid
   *   The deciding user's id.
   * @param int $timestamp
   *   The decision timestamp.
   *
   * @return $this
   */
  public function setDecision(int $uid, int $timestamp): static;

}
