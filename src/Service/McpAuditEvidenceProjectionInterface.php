<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Applies one selected evidence policy to enriched audit metadata.
 *
 * Implementations must be immutable and use an allowlist of values safe for
 * the selected operation. Sentinel never queues the original metadata when
 * a projection is selected.
 */
interface McpAuditEvidenceProjectionInterface {

  /**
   * Returns the complete metadata allowed in the audit row.
   *
   * @param string $operation
   *   The recorded operation.
   * @param array<string, mixed> $metadata
   *   Enriched metadata, including any automatic audit attribution.
   *
   * @return array<string, mixed>
   *   Only the permitted metadata.
   */
  public function project(string $operation, array $metadata): array;

}
