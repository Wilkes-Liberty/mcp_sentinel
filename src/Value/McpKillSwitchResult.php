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
   *   TRUE when the named second person (secondary account holder)
   *   must still confirm.
   * @param int $blockUntil
   *   Unix timestamp when the block expires. 0 when not yet killed.
   * @param int $ttl
   *   Applied TTL in seconds.
   * @param list<\Drupal\mcp_sentinel\Value\McpKillSelector> $selectors
   *   Targets in this batch.
   */
  public function __construct(
    public McpKillBlockStatus $status,
    public string $batchId,
    public bool $needsConfirm,
    public int $blockUntil,
    public int $ttl,
    public array $selectors,
  ) {}

}
