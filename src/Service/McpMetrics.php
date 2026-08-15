<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\State\StateInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Psr\Log\LoggerInterface;

/**
 * Single source of governance-dashboard data.
 *
 * Aggregates from existing stores only — the audit chain,
 * mcp_sentinel_webhook_delivery, approval entities (NULL-safe when the
 * submodule is absent), anomaly @state, and config. Every audit/webhook query
 * is bounded to the selected window via the already-indexed timestamp/created
 * columns and uses the parameterized DB API (no string-interpolated SQL, no
 * full table scans). The $window parameter is validated against a fixed
 * allowlist (24h/7d/30d) and mapped to seconds; any other value defaults to
 * 24h so a caller can never inject an arbitrary bound.
 *
 * Each public method is defensive: a failure in one metric is logged and
 * degrades to a safe empty/zero value rather than throwing out of the service
 * (the controller additionally guards per-widget). Results are statically
 * cached per request, keyed by method + window.
 */
final class McpMetrics {

  /**
   * Allowlisted dashboard windows mapped to their length in seconds.
   */
  private const WINDOWS = [
    '24h' => 86400,
    '7d' => 604800,
    '30d' => 2592000,
  ];

  /**
   * The default window used when an unknown value is supplied.
   */
  private const DEFAULT_WINDOW = '24h';

  /**
   * Operation strings that represent a denial / security event.
   *
   * These match the strings the module actually writes: 'denied_access' from
   * McpEntityToolTrait::logDeniedAccess(), 'rate_limit_exceeded' from
   * McpEntityToolTrait::checkRateLimit(), 'read_budget_denied' from the
   * budget seams, 'classification_egress_denied' from the classification
   * resolver, 'config_write_denied' from the config-save subscriber,
   * 'raw_sql_denied' from the governed drush command, and 'evidence_veto'
   * from the evidence guard. A refusal that is not listed here is invisible
   * to the dashboard's denial rollup, so a new denial operation belongs here
   * the day it is introduced (d.o #3616540 part 2).
   */
  private const DENIED_OPERATIONS = [
    'denied_access',
    'rate_limit_exceeded',
    'read_budget_denied',
    'classification_egress_denied',
    'config_write_denied',
    'raw_sql_denied',
    'evidence_veto',
  ];

  /**
   * Per-request static result cache, keyed by "method:window".
   *
   * @var array<string, mixed>
   */
  private array $staticCache = [];

  /**
   * Constructs an McpMetrics service.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\State\StateInterface $state
   *   The state service (anomaly alerts + last-verify result).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (approval entity, profile count).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger (encryption-safe metadata decoding).
   * @param \Psr\Log\LoggerInterface $logger
   *   The mcp_sentinel logger channel.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StateInterface $state,
    private readonly TimeInterface $time,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly McpAuditLogger $auditLogger,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Returns the high-level posture rollup.
   *
   * @return array{governed: bool, profile_count: int, channel_validated: bool}
   *   Governance on/off, policy-profile count, and whether at least one OAuth
   *   agent client is configured (the validated agent channel).
   */
  public function statusSummary(): array {
    return $this->guard(__FUNCTION__, NULL, [
      'governed' => FALSE,
      'profile_count' => 0,
      'channel_validated' => FALSE,
    ], function (): array {
      $config = $this->configFactory->get('mcp_sentinel.settings');
      $clients = (array) ($config->get('agent_oauth_clients') ?? []);
      return [
        'governed' => (bool) $config->get('enabled'),
        'profile_count' => count($this->profileIds()),
        'channel_validated' => $clients !== [],
      ];
    });
  }

  /**
   * Returns total and denied audit-write counts within the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array{total: int, denied: int}
   *   Total rows and denied/security rows in the window.
   */
  public function auditCounts(string $window): array {
    return $this->guard(__FUNCTION__, $window, ['total' => 0, 'denied' => 0], function () use ($window): array {
      $since = $this->since($window);
      $total = (int) $this->auditBaseQuery($since)
        ->countQuery()->execute()->fetchField();
      $denied = (int) $this->auditBaseQuery($since)
        ->condition('operation', self::DENIED_OPERATIONS, 'IN')
        ->countQuery()->execute()->fetchField();
      return ['total' => $total, 'denied' => $denied];
    });
  }

  /**
   * Returns a bucketed volume time series for the window.
   *
   * Buckets by hour for 24h and by day for 7d/30d. Buckets that coincide with a
   * fired anomaly alert (from @state) are flagged.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array<string, array{count: int, anomaly: bool}>
   *   Bucket label => count + anomaly flag, in ascending time order.
   */
  public function auditTimeSeries(string $window): array {
    return $this->guard(__FUNCTION__, $window, [], function () use ($window): array {
      $window = $this->normalizeWindow($window);
      $now = $this->time->getRequestTime();
      $since = $now - self::WINDOWS[$window];
      $bucketSeconds = $window === '24h' ? 3600 : 86400;

      // Pull the bounded rows (indexed timestamp), bucket in PHP to stay
      // database-agnostic across MySQL/PostgreSQL.
      $rows = $this->auditBaseQuery($since)
        ->fields('l', ['timestamp'])
        ->execute();

      $counts = [];
      foreach ($rows as $row) {
        $bucket = (int) (floor(((int) $row->timestamp) / $bucketSeconds) * $bucketSeconds);
        $counts[$bucket] = ($counts[$bucket] ?? 0) + 1;
      }

      $alertTimes = $this->anomalyAlertTimes($since);

      $series = [];
      for ($t = (int) (floor($since / $bucketSeconds) * $bucketSeconds); $t <= $now; $t += $bucketSeconds) {
        $label = $window === '24h' ? date('H:i', $t) : date('M j', $t);
        $hasAlert = FALSE;
        foreach ($alertTimes as $alertTime) {
          if ($alertTime >= $t && $alertTime < $t + $bucketSeconds) {
            $hasAlert = TRUE;
            break;
          }
        }
        $series[$label] = [
          'count' => $counts[$t] ?? 0,
          'anomaly' => $hasAlert,
        ];
      }
      return $series;
    });
  }

  /**
   * Returns the allowed vs. denied split within the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array{allowed: int, denied: int}
   *   Allowed (non-denial) and denied operation counts.
   */
  public function allowedVsDenied(string $window): array {
    return $this->guard(__FUNCTION__, $window, ['allowed' => 0, 'denied' => 0], function () use ($window): array {
      $counts = $this->auditCounts($window);
      return [
        'allowed' => max($counts['total'] - $counts['denied'], 0),
        'denied' => $counts['denied'],
      ];
    });
  }

  /**
   * Returns a count of audit rows by operation type within the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array<string, int>
   *   Operation string => count, highest first.
   */
  public function operationMix(string $window): array {
    return $this->guard(__FUNCTION__, $window, [], function () use ($window): array {
      $since = $this->since($window);
      $query = $this->auditBaseQuery($since);
      $query->addField('l', 'operation', 'operation');
      $query->addExpression('COUNT(*)', 'cnt');
      $query->groupBy('l.operation');
      $mix = [];
      foreach ($query->execute() as $row) {
        $mix[(string) $row->operation] = (int) $row->cnt;
      }
      arsort($mix);
      return $mix;
    });
  }

  /**
   * Returns the busiest agent identities within the window.
   *
   * Agent identity is the audit row's uid (the authenticated OAuth subject the
   * module attributes each governed write to).
   *
   * @param string $window
   *   One of 24h/7d/30d.
   * @param int $limit
   *   Maximum number of agents to return.
   *
   * @return array<int, array{uid: int, total: int, denied: int}>
   *   Agents ordered by total volume descending.
   */
  public function topAgents(string $window, int $limit = 5): array {
    return $this->guard(__FUNCTION__, $window . ':' . $limit, [], function () use ($window, $limit): array {
      $since = $this->since($window);
      $query = $this->auditBaseQuery($since);
      $query->addField('l', 'uid', 'uid');
      $query->addExpression('COUNT(*)', 'total');
      // Use explicit scalar placeholders for the CASE expression so it is safe
      // on both MySQL/MariaDB and PostgreSQL (the :name[] array-expansion
      // convention is only documented for condition() and does not reliably
      // bind inside addExpression() on pgsql).
      // One placeholder per listed operation, built from the constant so the
      // rollup cannot silently under-count when the list grows.
      $placeholders = [];
      $arguments = [];
      foreach (array_values(self::DENIED_OPERATIONS) as $i => $operation) {
        $placeholders[] = ':denied_op' . $i;
        $arguments[':denied_op' . $i] = $operation;
      }
      $denied = 'SUM(CASE WHEN l.operation IN (' . implode(', ', $placeholders) . ') THEN 1 ELSE 0 END)';
      $query->addExpression($denied, 'denied', $arguments);
      $query->groupBy('l.uid');
      $query->orderBy('total', 'DESC');
      $query->range(0, max($limit, 1));
      $agents = [];
      foreach ($query->execute() as $row) {
        $agents[] = [
          'uid' => (int) $row->uid,
          'total' => (int) $row->total,
          'denied' => (int) $row->denied,
        ];
      }
      return $agents;
    });
  }

  /**
   * Returns denial counts grouped by reason within the window.
   *
   * Reasons are read from each denied_access row's metadata via the audit
   * logger's encryption-safe decodeMetadata() accessor (the reason is stored
   * under the 'reason' metadata key by McpEntityToolTrait::logDeniedAccess()).
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array<string, int>
   *   Reason => count, highest first.
   */
  public function deniedReasons(string $window): array {
    return $this->guard(__FUNCTION__, $window, [], function () use ($window): array {
      $since = $this->since($window);
      $rows = $this->auditBaseQuery($since)
        ->fields('l', ['operation', 'metadata'])
        ->condition('operation', self::DENIED_OPERATIONS, 'IN')
        ->execute();
      $reasons = [];
      foreach ($rows as $row) {
        $meta = $this->auditLogger->decodeMetadata((string) ($row->metadata ?? ''));
        if (isset($meta['reason']) && $meta['reason'] !== '') {
          // denied_access rows carry an explicit 'reason' metadata key.
          $reason = (string) $meta['reason'];
        }
        else {
          // rate_limit_exceeded (and future denial ops) carry no 'reason' key;
          // use the operation string as the label so the returned map
          // distinguishes rate-limit throttles from policy denials.
          $reason = (string) $row->operation;
        }
        $reasons[$reason] = ($reasons[$reason] ?? 0) + 1;
      }
      arsort($reasons);
      return $reasons;
    });
  }

  /**
   * Returns webhook delivery health within the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array{sent: int, failed: int, pending: int, total: int, success_rate: float}
   *   Delivery counts by status plus the success rate (sent / resolved).
   */
  public function webhookHealth(string $window): array {
    $default = [
      'sent' => 0,
      'failed' => 0,
      'pending' => 0,
      'total' => 0,
      'success_rate' => 0.0,
    ];
    return $this->guard(__FUNCTION__, $window, $default, function () use ($window): array {
      $since = $this->since($window);
      $query = $this->database->select('mcp_sentinel_webhook_delivery', 'd');
      $query->condition('d.created', $since, '>=');
      $query->addField('d', 'status', 'status');
      $query->addExpression('COUNT(*)', 'cnt');
      $query->groupBy('d.status');
      $byStatus = [];
      foreach ($query->execute() as $row) {
        $byStatus[(string) $row->status] = (int) $row->cnt;
      }
      // 'failed', 'failed_ssrf', 'failed_redirect' and 'failed_key' are
      // terminal failures; 'in_progress' is pending for dashboard purposes.
      $sent = $byStatus['sent'] ?? 0;
      $failed = ($byStatus['failed'] ?? 0) + ($byStatus['failed_ssrf'] ?? 0)
        + ($byStatus['failed_redirect'] ?? 0) + ($byStatus['failed_key'] ?? 0);
      $pending = ($byStatus['pending'] ?? 0) + ($byStatus['in_progress'] ?? 0);
      $total = $sent + $failed + $pending;
      $resolved = $sent + $failed;
      return [
        'sent' => $sent,
        'failed' => $failed,
        'pending' => $pending,
        'total' => $total,
        'success_rate' => $resolved > 0 ? round(($sent / $resolved) * 100, 1) : 0.0,
      ];
    });
  }

  /**
   * Returns the pending-approval summary (NULL-safe when submodule absent).
   *
   * @return array{pending: int, oldest_age: int|null, available: bool}
   *   Pending count, oldest pending age in seconds (NULL when none), and
   *   whether the approval submodule is installed.
   */
  public function approvalSummary(): array {
    return $this->guard(__FUNCTION__, NULL, ['pending' => 0, 'oldest_age' => NULL, 'available' => FALSE], function (): array {
      if (!$this->entityTypeManager->hasDefinition('mcp_approval_request')) {
        return ['pending' => 0, 'oldest_age' => NULL, 'available' => FALSE];
      }
      $storage = $this->entityTypeManager->getStorage('mcp_approval_request');
      $ids = $storage->getQuery()
        ->accessCheck(FALSE)
        ->condition('status', 'pending')
        ->sort('created', 'ASC')
        ->execute();
      $oldestAge = NULL;
      if ($ids !== []) {
        $first = $storage->load(reset($ids));
        if ($first instanceof ContentEntityInterface) {
          $created = (int) $first->get('created')->value;
          $oldestAge = max($this->time->getRequestTime() - $created, 0);
        }
      }
      return [
        'pending' => count($ids),
        'oldest_age' => $oldestAge,
        'available' => TRUE,
      ];
    });
  }

  /**
   * Returns the anomaly-detection summary for the window.
   *
   * @param string $window
   *   One of 24h/7d/30d.
   *
   * @return array{alerts: int, enabled_rules: int}
   *   Alerts fired within the window (from @state debounce timestamps) and the
   *   number of enabled rules in config.
   */
  public function anomalySummary(string $window): array {
    return $this->guard(__FUNCTION__, $window, ['alerts' => 0, 'enabled_rules' => 0], function () use ($window): array {
      $config = $this->configFactory->get('mcp_sentinel.settings');
      $enabled = 0;
      foreach ((array) ($config->get('anomaly_rules') ?? []) as $rule) {
        if (is_array($rule) && !empty($rule['enabled'])) {
          $enabled++;
        }
      }
      return [
        'alerts' => count($this->anomalyAlertTimes($this->since($window))),
        'enabled_rules' => $enabled,
      ];
    });
  }

  /**
   * Returns the stored hash-chain integrity result (does NOT re-verify).
   *
   * Reads the cached last-verify result from @state key
   * 'mcp_sentinel.last_verify' (written by the explicit "Verify now" action /
   * Drush). verifyChain() is intentionally never called on this hot path.
   *
   * @return array{ok: bool|null, broken_at: int|null, verified_at: int|null, rows: int}
   *   The last-verify outcome (ok NULL when never verified) and the current
   *   audit row count.
   */
  public function chainIntegrity(): array {
    return $this->guard(__FUNCTION__, NULL, ['ok' => NULL, 'broken_at' => NULL, 'verified_at' => NULL, 'rows' => 0], function (): array {
      $last = $this->state->get('mcp_sentinel.last_verify');
      $rows = (int) $this->database->select('audit_chain_log', 'l')
        ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
        ->countQuery()->execute()->fetchField();
      if (!is_array($last)) {
        return ['ok' => NULL, 'broken_at' => NULL, 'verified_at' => NULL, 'rows' => $rows];
      }
      return [
        'ok' => isset($last['ok']) ? (bool) $last['ok'] : NULL,
        'broken_at' => isset($last['broken_at']) ? (int) $last['broken_at'] : NULL,
        'verified_at' => isset($last['time']) ? (int) $last['time'] : NULL,
        'rows' => $rows,
      ];
    });
  }

  /**
   * Returns which security controls are currently active.
   *
   * @return array<string, bool>
   *   Control name => enabled, for hash_chain, encryption, siem, dlp,
   *   rate_limit, ip_allowlist, and approvals.
   */
  public function activeControls(): array {
    $default = [
      'hash_chain' => FALSE,
      'encryption' => FALSE,
      'siem' => FALSE,
      'dlp' => FALSE,
      'rate_limit' => FALSE,
      'ip_allowlist' => FALSE,
      'approvals' => FALSE,
    ];
    return $this->guard(__FUNCTION__, NULL, $default, function (): array {
      $config = $this->configFactory->get('mcp_sentinel.settings');
      $chainConfig = $this->configFactory->get('audit_chain.settings');
      [$rateLimit, $ipAllowlist] = $this->profileControls();
      return [
        // Read from audit_chain.settings: these controls moved with the chain,
        // and reporting them from the old keys would show every site as having
        // no signing key and no encryption the moment it upgraded.
        'hash_chain' => (string) ($chainConfig->get('hash_key') ?? '') !== '',
        'encryption' => (string) ($chainConfig->get('encryption_profile') ?? '') !== '',
        'siem' => (bool) $chainConfig->get('stream_enabled'),
        'dlp' => (bool) $config->get('dlp_enabled'),
        'rate_limit' => $rateLimit,
        'ip_allowlist' => $ipAllowlist,
        'approvals' => $this->entityTypeManager->hasDefinition('mcp_approval_request'),
      ];
    });
  }

  /**
   * Builds a window-bounded base SELECT over the audit log.
   *
   * Uses the indexed timestamp column with a parameterized lower bound; never
   * scans the whole table.
   *
   * @param int $since
   *   The lower-bound timestamp (inclusive).
   *
   * @return \Drupal\Core\Database\Query\SelectInterface
   *   The bounded query, ready for further conditions/aggregation.
   */
  private function auditBaseQuery(int $since): object {
    return $this->database->select('audit_chain_log', 'l')
      ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
      ->condition('l.timestamp', $since, '>=');
  }

  /**
   * Returns the fired-anomaly timestamps at or after the given lower bound.
   *
   * Reads the per-rule debounce timestamps written by McpAnomalyDetector under
   * 'mcp_sentinel.anomaly_last_alert.{rule_id}'.
   *
   * @param int $since
   *   The lower-bound timestamp (inclusive).
   *
   * @return int[]
   *   Alert timestamps within the window.
   */
  private function anomalyAlertTimes(int $since): array {
    $times = [];
    foreach ((array) $this->configFactory->get('mcp_sentinel.settings')->get('anomaly_rules') as $rule) {
      if (!is_array($rule) || ($rule['id'] ?? '') === '') {
        continue;
      }
      $ts = (int) $this->state->get('mcp_sentinel.anomaly_last_alert.' . $rule['id'], 0);
      if ($ts >= $since && $ts > 0) {
        $times[] = $ts;
      }
    }
    return $times;
  }

  /**
   * Returns the configured policy-profile IDs.
   *
   * @return string[]
   *   Profile entity IDs (empty when none / on error).
   */
  private function profileIds(): array {
    if (!$this->entityTypeManager->hasDefinition('mcp_policy_profile')) {
      return [];
    }
    return array_values($this->entityTypeManager
      ->getStorage('mcp_policy_profile')
      ->getQuery()
      ->accessCheck(FALSE)
      ->execute());
  }

  /**
   * Returns whether any profile enables rate limiting or an IP allowlist.
   *
   * @return array{0: bool, 1: bool}
   *   [rate_limit_active, ip_allowlist_active].
   */
  private function profileControls(): array {
    $rateLimit = FALSE;
    $ipAllowlist = FALSE;
    if (!$this->entityTypeManager->hasDefinition('mcp_policy_profile')) {
      return [$rateLimit, $ipAllowlist];
    }
    $profiles = $this->entityTypeManager->getStorage('mcp_policy_profile')->loadMultiple();
    foreach ($profiles as $profile) {
      if (!$profile instanceof McpPolicyProfileInterface) {
        continue;
      }
      if ($profile->getRateLimitRequests() > 0) {
        $rateLimit = TRUE;
      }
      if ($profile->getAllowedIps() !== []) {
        $ipAllowlist = TRUE;
      }
    }
    return [$rateLimit, $ipAllowlist];
  }

  /**
   * Validates a window string against the allowlist, defaulting to 24h.
   *
   * @param string $window
   *   The requested window.
   *
   * @return string
   *   A guaranteed-valid window key.
   */
  private function normalizeWindow(string $window): string {
    return isset(self::WINDOWS[$window]) ? $window : self::DEFAULT_WINDOW;
  }

  /**
   * Returns the lower-bound timestamp for the (normalized) window.
   *
   * @param string $window
   *   The requested window.
   *
   * @return int
   *   The inclusive lower-bound Unix timestamp.
   */
  private function since(string $window): int {
    return $this->time->getRequestTime() - self::WINDOWS[$this->normalizeWindow($window)];
  }

  /**
   * Runs a metric callback with static caching and defensive error handling.
   *
   * @param string $method
   *   The calling method name (cache namespace).
   * @param string|null $window
   *   The window suffix for the cache key, or NULL for window-less metrics.
   * @param mixed $default
   *   The safe value to return if the callback throws.
   * @param callable $callback
   *   The metric computation.
   *
   * @return mixed
   *   The computed (and cached) value, or $default on failure.
   */
  private function guard(string $method, ?string $window, mixed $default, callable $callback): mixed {
    $key = $method . ':' . ($window ?? '');
    if (array_key_exists($key, $this->staticCache)) {
      return $this->staticCache[$key];
    }
    try {
      $value = $callback();
    }
    catch (\Throwable $e) {
      $this->logger->error('McpMetrics::@method failed: @message', [
        '@method' => $method,
        '@message' => $e->getMessage(),
      ]);
      $value = $default;
    }
    $this->staticCache[$key] = $value;
    return $value;
  }

}
