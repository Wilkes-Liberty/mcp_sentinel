<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * One prepared fired-rule result for alert rendering and metadata.
 *
 * Built once per rule so the email, audit row, webhook payload, and
 * log context share the same identity and grouping.
 */
final readonly class McpAnomalyPreparedRule {

  /**
   * Constructs a prepared fired-rule result.
   *
   * @param array<string, mixed> $rule
   *   The rule map.
   * @param int $count
   *   Matching-row count that tripped the rule.
   * @param int $window
   *   Lookback window in seconds.
   * @param int $threshold
   *   Configured threshold.
   * @param string $signal
   *   Rule signal: count, off_hours, or bulk_read.
   * @param array{site: string, host: string, environment: string} $identity
   *   Site, host URL, and environment for the sending process.
   * @param array{scanned: int, sources: list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>, reasons: array<string, int>, tenants: array<string, int>, groups: list<array{host: string, client: string, mcp_client: string, origin: string, ip: string, reason: string, count: int}>} $summary
   *   Bounded grouping of matching rows.
   */
  public function __construct(
    public array $rule,
    public int $count,
    public int $window,
    public int $threshold,
    public string $signal,
    public array $identity,
    public array $summary,
  ) {}

}
