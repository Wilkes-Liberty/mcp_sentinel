<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Query\SelectInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\State\StateInterface;

/**
 * Evaluates anomaly-detection rules over the MCP audit log stream.
 *
 * Each cron run evaluates all enabled rules. Rules that exceed their threshold
 * fire an alert. Debounce prevents repeated alerts within the configured
 * window. All queries hit the indexed 'operation' + 'timestamp' columns of
 * the audit chain.
 *
 * Debounce state is stored under the key:
 *   mcp_sentinel.anomaly_last_alert.{rule_id}
 * A rule fires at most once per debounce_seconds (default 3600).
 * Set debounce_seconds to 0 to disable debouncing for a rule.
 */
final class McpAnomalyDetector {

  /**
   * Default debounce window in seconds (1 hour).
   */
  private const DEFAULT_DEBOUNCE_SECONDS = 3600;

  /**
   * Constructs a new McpAnomalyDetector.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Drupal\Core\State\StateInterface $state
   *   The state service for debounce timestamps.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface|null $entityTypeManager
   *   Used by bulk-read to size the live collection. NULL in isolated tests.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StateInterface $state,
    private readonly TimeInterface $time,
    private readonly ?EntityTypeManagerInterface $entityTypeManager = NULL,
  ) {}

  /**
   * Evaluates all enabled rules against recent audit rows.
   *
   * Returns an array of fired-rule results; empty when no rules trigger or
   * anomaly detection is globally disabled. Each entry has the shape:
   *   ['rule' => array, 'count' => int]
   *
   * @return array<array{rule: array, count: int}>
   *   Fired rule results; empty when no rules trigger or detection is disabled.
   */
  public function evaluate(): array {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    if (!$config->get('anomaly_enabled')) {
      return [];
    }
    $fired = [];
    $now = $this->time->getRequestTime();
    foreach ((array) $config->get('anomaly_rules') as $rule) {
      if (!is_array($rule) || empty($rule['enabled'])) {
        continue;
      }
      // Validate required fields — skip malformed rules rather than fataling.
      $ruleId = (string) ($rule['id'] ?? '');
      $pattern = (string) ($rule['operation_pattern'] ?? '');
      $threshold = (int) ($rule['threshold'] ?? 0);
      $window = (int) ($rule['window_seconds'] ?? 0);
      if ($ruleId === '' || $pattern === '' || $threshold <= 0 || $window <= 0) {
        continue;
      }

      // Debounce check: suppress if an alert fired within debounce_seconds.
      $debounce = (int) ($rule['debounce_seconds'] ?? self::DEFAULT_DEBOUNCE_SECONDS);
      if ($debounce > 0) {
        $stateKey = 'mcp_sentinel.anomaly_last_alert.' . $ruleId;
        $lastAlert = (int) $this->state->get($stateKey, 0);
        if (($now - $lastAlert) < $debounce) {
          // Still within debounce window; suppress.
          continue;
        }
      }

      // Count matching audit rows within the lookback window.
      $since = $now - $window;
      $signal = (string) ($rule['signal'] ?? 'count');
      $count = match ($signal) {
        'off_hours' => $this->countOffHours($pattern, $since, $config),
        'bulk_read' => $this->countBulkRead($pattern, $since, $rule),
        default => $this->countOps($pattern, $since),
      };

      if ($count >= $threshold) {
        $fired[] = ['rule' => $rule, 'count' => $count];
        // Record debounce timestamp (only when debounce is enabled).
        if ($debounce > 0) {
          $this->state->set('mcp_sentinel.anomaly_last_alert.' . $ruleId, $now);
        }
      }
    }
    return $fired;
  }

  /**
   * Counts audit log rows matching an operation pattern within a time window.
   *
   * Queries only the indexed 'operation' and 'timestamp' columns to stay cheap
   * on large audit tables.
   *
   * Match semantics (set via the rule's operation_pattern field):
   *   - Exact match (default): the pattern is compared with = so that 'entity'
   *     matches only 'entity' and NOT 'entity_save' or 'entity_delete'. This is
   *     the safe default; short patterns never silently swallow unrelated ops.
   *   - Prefix match (opt-in): append a trailing '*' to use LIKE with a '%'
   *     wildcard. For example, 'entity*' matches 'entity_save' and
   *     'entity_delete'. The '*' is stripped before the SQL comparison.
   *
   * @param string $pattern
   *   The operation pattern. A trailing '*' enables prefix matching; without it
   *   an exact = comparison is used.
   * @param int $since
   *   Unix timestamp; only rows newer than this time are counted.
   *
   * @return int
   *   Number of matching rows.
   */
  private function countOps(string $pattern, int $since): int {
    $query = $this->database
      ->select('audit_chain_log', 'l')
      ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
      ->condition('l.timestamp', $since, '>');

    if (str_ends_with($pattern, '*')) {
      // Prefix match: strip the trailing '*' and use LIKE with '%'.
      $prefix = substr($pattern, 0, -1);
      $query->condition('l.operation', $this->database->escapeLike($prefix) . '%', 'LIKE');
    }
    else {
      // Exact match (default): no LIKE, no implicit wildcard expansion.
      $query->condition('l.operation', $pattern);
    }

    return (int) $query->countQuery()->execute()->fetchField();
  }

  /**
   * Counts matching operations whose timestamp falls outside operating hours.
   *
   * When the schedule is disabled, off-hours rules do not fire (count 0).
   *
   * @param string $pattern
   *   Operation pattern (same semantics as countOps()).
   * @param int $since
   *   Lookback start.
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   Module settings.
   */
  private function countOffHours(string $pattern, int $since, ImmutableConfig $config): int {
    if (!(bool) $config->get('anomaly_hours_enabled')) {
      return 0;
    }
    $query = $this->opsQuery($pattern, $since)->fields('l', ['timestamp']);
    $count = 0;
    foreach ($query->execute() as $row) {
      if ($this->isOffHours((int) $row->timestamp, $config)) {
        $count++;
      }
    }
    return $count;
  }

  /**
   * Whether a unix timestamp is outside the configured operating-hours window.
   */
  public function isOffHours(int $timestamp, ?ImmutableConfig $config = NULL): bool {
    $config ??= $this->configFactory->get('mcp_sentinel.settings');
    if (!(bool) $config->get('anomaly_hours_enabled')) {
      return FALSE;
    }
    $tzName = (string) ($config->get('anomaly_hours_timezone') ?? 'UTC');
    try {
      $tz = new \DateTimeZone($tzName !== '' ? $tzName : 'UTC');
    }
    catch (\Throwable) {
      $tz = new \DateTimeZone('UTC');
    }
    $local = (new \DateTimeImmutable('@' . $timestamp))->setTimezone($tz);
    $days = array_map('intval', (array) ($config->get('anomaly_hours_days') ?? [1, 2, 3, 4, 5]));
    $dow = (int) $local->format('N');
    if ($days !== [] && !in_array($dow, $days, TRUE)) {
      return TRUE;
    }
    $start = (string) ($config->get('anomaly_hours_start') ?? '09:00');
    $end = (string) ($config->get('anomaly_hours_end') ?? '17:00');
    $hm = $local->format('H:i');
    if ($start <= $end) {
      return $hm < $start || $hm >= $end;
    }
    // Overnight window (e.g. 22:00–06:00): on-hours wrap midnight.
    return $hm < $start && $hm >= $end;
  }

  /**
   * Counts distinct entity IDs read in the window for complete bulk-read.
   *
   * Returns the distinct-read count when it meets the absolute threshold or
   * the complete-ratio of the live collection size; otherwise 0 so the
   * existing `>= threshold` comparison stays deterministic.
   *
   * @param string $pattern
   *   Operation pattern (typically entity_read*).
   * @param int $since
   *   Lookback start.
   * @param array $rule
   *   The rule map (threshold, optional complete_ratio and entity_type).
   */
  private function countBulkRead(string $pattern, int $since, array $rule): int {
    $query = $this->opsQuery($pattern, $since)->fields('l', ['entity_type', 'entity_id']);
    $byType = [];
    foreach ($query->execute() as $row) {
      $type = (string) $row->entity_type;
      $id = (string) $row->entity_id;
      if ($type === '' || $id === '') {
        continue;
      }
      $byType[$type][$id] = TRUE;
    }
    $only = trim((string) ($rule['entity_type'] ?? ''));
    if ($only !== '') {
      $byType = isset($byType[$only]) ? [$only => $byType[$only]] : [];
    }
    $threshold = (int) ($rule['threshold'] ?? 0);
    $ratio = (float) ($rule['complete_ratio'] ?? 0.8);
    if ($ratio <= 0 || $ratio > 1) {
      $ratio = 0.8;
    }
    $best = 0;
    foreach ($byType as $type => $ids) {
      $distinct = count($ids);
      $best = max($best, $distinct);
      $total = $this->entityCount($type);
      if ($distinct >= $threshold) {
        return $distinct;
      }
      if ($total > 0 && $distinct >= (int) ceil($total * $ratio)) {
        return max($distinct, $threshold);
      }
    }
    return $best >= $threshold ? $best : 0;
  }

  /**
   * Live entity count for a type, or 0 when the type is unknown.
   */
  private function entityCount(string $entityTypeId): int {
    if ($this->entityTypeManager === NULL || !$this->entityTypeManager->hasDefinition($entityTypeId)) {
      return 0;
    }
    try {
      return (int) $this->entityTypeManager->getStorage($entityTypeId)->getQuery()
        ->accessCheck(FALSE)
        ->count()
        ->execute();
    }
    catch (\Throwable) {
      return 0;
    }
  }

  /**
   * Shared audit query for an operation pattern in a window.
   */
  private function opsQuery(string $pattern, int $since): SelectInterface {
    $query = $this->database
      ->select('audit_chain_log', 'l')
      ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
      ->condition('l.timestamp', $since, '>');
    if (str_ends_with($pattern, '*')) {
      $prefix = substr($pattern, 0, -1);
      $query->condition('l.operation', $this->database->escapeLike($prefix) . '%', 'LIKE');
    }
    else {
      $query->condition('l.operation', $pattern);
    }
    return $query;
  }

}
