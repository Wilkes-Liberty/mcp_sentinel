<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;

/**
 * Outcome of a kill-switch operator action.
 */
final readonly class McpKillSwitchResult {

  /**
   * Constructs the result.
   *
   * @param \Drupal\mcp_sentinel\Enum\McpKillBlockStatus $status
   *   Resulting registry status.
   * @param string $batchId
   *   Batch id for confirm / unkill-confirm.
   * @param bool $needsConfirm
   *   TRUE when a distinct bound operator must still confirm.
   * @param int $blockUntil
   *   Unix timestamp when a confirmed stop expires. Non-zero while
   *   a mass freeze is pending. An unconfirmed freeze stays in
   *   force after this timestamp.
   * @param int $ttl
   *   Stored TTL in seconds (the enforced window).
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Targets in this batch.
   * @param int $requestedTtl
   *   TTL the operator asked for. 0 when the command
   *   does not take a TTL.
   * @param int $requestedBlockUntil
   *   Expiry computed from the requested TTL. 0 when
   *   the command does not take a TTL.
   */
  public function __construct(
    public McpKillBlockStatus $status,
    public string $batchId,
    public bool $needsConfirm,
    public int $blockUntil,
    public int $ttl,
    public array $selectors,
    public int $requestedTtl = 0,
    public int $requestedBlockUntil = 0,
  ) {}

}
