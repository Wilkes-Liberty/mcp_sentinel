<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Service;

use Drupal\Core\Config\ConfigFactoryInterface;

/**
 * Decides whether a destructive operation requires human approval.
 *
 * The set of gated operations is configurable via the
 * mcp_sentinel_approval.settings 'gated_operations' key (default: ['delete']).
 */
final class McpApprovalGate {

  /**
   * Constructs an McpApprovalGate.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Whether the given operation requires approval before executing.
   *
   * @param string $op
   *   The operation identifier (e.g. 'delete').
   *
   * @return bool
   *   TRUE when the operation is in the configured gated set.
   */
  public function requiresApproval(string $op): bool {
    $gated = (array) $this->configFactory
      ->get('mcp_sentinel_approval.settings')
      ->get('gated_operations');
    return in_array($op, $gated, TRUE);
  }

}
