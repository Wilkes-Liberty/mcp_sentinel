<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_test\Service;

use Drupal\mcp_sentinel\Service\McpKillBlockUntilReader;
use Drupal\mcp_sentinel\Service\McpKillBlockUntilReaderInterface;

/**
 * Test decorator that can force a fail-closed block_until read.
 *
 * Honours injectUnreadable($batchId) for one kill batch, or every
 * row when $batchId is empty.
 */
final class McpTestKillBlockUntilReader implements McpKillBlockUntilReaderInterface {

  /**
   * Batch ids whose stored block_until must read as unreadable.
   *
   * @var array<string, true>
   */
  private array $unreadableBatchIds = [];

  /**
   * TRUE when every row should fail closed.
   */
  private bool $allUnreadable = FALSE;

  /**
   * Batch ids whose seam read returns an expired timestamp.
   *
   * Production must ignore this and keep the stored block.
   *
   * @var array<string, true>
   */
  private array $expiredBatchIds = [];

  /**
   * Constructs the decorator.
   *
   * @param \Drupal\mcp_sentinel\Service\McpKillBlockUntilReader $inner
   *   Production typed reader.
   */
  public function __construct(
    private readonly McpKillBlockUntilReader $inner,
  ) {}

  /**
   * Treat stored block_until as unreadable for $batchId, or every row.
   *
   * @param string $batchId
   *   Kill batch to fail closed. Empty applies to every row.
   */
  public function injectUnreadable(string $batchId = ''): void {
    if ($batchId === '') {
      $this->allUnreadable = TRUE;
      return;
    }
    $this->unreadableBatchIds[$batchId] = TRUE;
  }

  /**
   * Return an expired int for $batchId (must not lift the block).
   *
   * @param string $batchId
   *   Kill batch whose seam read pretends the block expired.
   */
  public function injectExpired(string $batchId): void {
    $this->expiredBatchIds[$batchId] = TRUE;
  }

  /**
   * Unix timestamp from a kill-block row, or NULL when unreadable.
   *
   * @param array<string, mixed> $row
   *   Stored row.
   */
  public function read(array $row): ?int {
    $batchId = isset($row['batch_id']) && is_string($row['batch_id'])
      ? $row['batch_id']
      : '';
    if ($this->allUnreadable
      || ($batchId !== '' && isset($this->unreadableBatchIds[$batchId]))) {
      return NULL;
    }
    if ($batchId !== '' && isset($this->expiredBatchIds[$batchId])) {
      return 0;
    }
    return $this->inner->read($row);
  }

}
