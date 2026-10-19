<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Site\Settings;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Value\McpAnomalyPreparedRule;
use Drupal\mcp_sentinel\Value\McpStoredValue;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Bounded, non-secret evidence for anomaly alerts and operator summaries.
 *
 * Shared by McpAlertDispatcher (every fired rule) and the read-only
 * denied-access Drush command so the email body and the operator query
 * describe the same window with the same redaction rules. Tokens,
 * Authorization headers, request bodies, and other secret keys are never
 * copied into the output; only allowlisted forensic labels are read, then
 * redacted and DLP-scanned when DLP is enabled.
 */
final class McpAnomalyEvidence {

  /**
   * Maximum distinct groups returned for sources, reasons, or tenants.
   */
  public const TOP_N = 8;

  /**
   * Hard cap on --top for the denied-access summary command.
   */
  public const TOP_MAX = 32;

  /**
   * Maximum matching rows scanned when grouping (newest first).
   */
  public const SCAN_CAP = 2000;

  /**
   * Maximum lookback window in seconds (7 days).
   */
  public const WINDOW_MAX = 604800;

  /**
   * Maximum bytes kept for one label.
   */
  public const LABEL_MAX = 128;

  /**
   * Placeholder when a grouping key is absent.
   */
  public const MISSING = '(none)';

  /**
   * Placeholder when settings.php did not declare an environment.
   */
  public const ENV_UNSET = '(unset)';

  /**
   * Audit operation written when an operator runs the denied-access summary.
   */
  public const AUDIT_DENIED_ACCESS_SUMMARY = 'denied_access_summary';

  /**
   * Constructs the evidence builder.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Site and module configuration.
   * @param \Drupal\Core\Site\Settings $settings
   *   settings.php values. Environment is read from here, never config.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   Current request, used for the host URL when cron has one.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Decrypts stored metadata and records the operator read.
   * @param \Drupal\mcp_sentinel\Service\McpDlp $dlp
   *   Scans labels for configured PII patterns.
   * @param \Drupal\mcp_sentinel\Service\McpAnomalyDetector $detector
   *   Off-hours filter for rules whose signal is off_hours.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Request time for window bounds.
   * @param int $scanCap
   *   Maximum matching rows to decrypt when grouping. Tests may pass a
   *   smaller cap to prove truncation without seeding SCAN_CAP rows.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly Settings $settings,
    private readonly RequestStack $requestStack,
    private readonly McpAuditLogger $auditLogger,
    private readonly McpDlp $dlp,
    private readonly McpAnomalyDetector $detector,
    private readonly TimeInterface $time,
    private readonly int $scanCap = self::SCAN_CAP,
  ) {}

  /**
   * Site, host URL, and environment for the process sending the alert.
   *
   * @return array{site: string, host: string, environment: string}
   *   Bounded labels. Environment is `(unset)` when not declared.
   */
  public function siteIdentity(): array {
    $siteConfig = $this->configFactory->get('system.site');
    $name = McpStoredValue::string($siteConfig->get('name') ?? '');
    // Drupal Settings::get() is static; the injected instance is the test seam.
    // @phpstan-ignore staticMethod.dynamicCall
    $rawEnv = $this->settings->get('mcp_sentinel.environment');
    $environment = is_string($rawEnv) ? $rawEnv : '';
    return [
      'site' => $name !== '' ? $this->label($name) : self::MISSING,
      'host' => $this->hostUrl(),
      'environment' => $environment !== ''
        ? $this->label($environment)
        : self::ENV_UNSET,
    ];
  }

  /**
   * Groups matching rows in the lookback window.
   *
   * @param string $pattern
   *   Operation pattern (same semantics as the detector).
   * @param int $since
   *   Exclusive lower bound on timestamp.
   * @param string $signal
   *   Rule signal: count, off_hours, or bulk_read.
   * @param array<string, mixed> $rule
   *   The rule map (optional entity_type for bulk_read).
   * @param int $topN
   *   Maximum groups per list.
   *
   * @return array{scanned: int, sources: list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>, reasons: array<string, int>, tenants: array<string, int>, groups: list<array{host: string, client: string, mcp_client: string, origin: string, ip: string, reason: string, count: int}>}
   *   Bounded counts. Groups are the Drush combination of host, client,
   *   Origin, IP, and reason.
   */
  public function summarize(
    string $pattern,
    int $since,
    string $signal = 'count',
    array $rule = [],
    int $topN = self::TOP_N,
  ): array {
    $topN = max(1, min($topN, self::TOP_MAX));
    $config = $this->configFactory->get('mcp_sentinel.settings');
    $query = McpAuditOperationQuery::selectMatching(
      $this->database,
      $pattern,
      $since,
    )
      ->fields('l', ['metadata', 'ip_address', 'entity_type', 'timestamp'])
      ->orderBy('l.timestamp', 'DESC')
      ->range(0, $this->scanCap);
    $entityType = McpStoredValue::string($rule['entity_type'] ?? '');
    $only = $signal === 'bulk_read' ? trim($entityType) : '';

    $sourceCounts = [];
    $reasonCounts = [];
    $tenantCounts = [];
    $groupCounts = [];
    $scanned = 0;
    $statement = $query->execute();
    if ($statement === NULL) {
      return $this->emptySummary();
    }
    while ($fetched = $statement->fetchAssoc()) {
      $row = McpStoredValue::stringKeyedRow($fetched);
      if ($row === NULL) {
        continue;
      }
      $offHours = $signal === 'off_hours'
        && !$this->detector->isOffHours(
          McpStoredValue::rowInt($row, 'timestamp'),
          $config,
        );
      if ($offHours) {
        continue;
      }
      $type = McpStoredValue::rowString($row, 'entity_type');
      if ($only !== '' && $type !== $only) {
        continue;
      }
      $scanned++;
      $stored = McpStoredValue::rowString($row, 'metadata');
      $decoded = $this->auditLogger->decodeMetadata($stored);
      $meta = McpStoredValue::stringKeyedRow($decoded) ?? [];
      $client = $this->firstLabel($meta, ['client_id', 'azp']);
      $mcpClient = $this->firstLabel($meta, ['mcp_client']);
      $principal = $this->firstLabel($meta, ['principal_key', 'human_key']);
      $origin = $this->firstLabel($meta, ['http_origin']);
      $host = $this->firstLabel($meta, ['http_host']);
      $reason = $this->firstLabel($meta, ['reason']);
      $tenant = $this->firstLabel($meta, ['tenant']);
      $ip = $this->label(McpStoredValue::rowString($row, 'ip_address'));
      $metaIp = $meta['ip'] ?? NULL;
      if ($ip === self::MISSING && is_string($metaIp)) {
        $ip = $this->label($metaIp);
      }

      $sourceKey = implode("\0", [
        $client,
        $mcpClient,
        $principal,
        $origin,
        $host,
        $ip,
      ]);
      $sourceCounts[$sourceKey] = [
        'client' => $client,
        'mcp_client' => $mcpClient,
        'principal' => $principal,
        'origin' => $origin,
        'host' => $host,
        'ip' => $ip,
        'count' => McpStoredValue::int($sourceCounts[$sourceKey]['count'] ?? 0) + 1,
      ];
      $reasonCounts[$reason] = ($reasonCounts[$reason] ?? 0) + 1;
      $tenantCounts[$tenant] = ($tenantCounts[$tenant] ?? 0) + 1;
      $groupKey = implode("\0", [
        $host,
        $client,
        $mcpClient,
        $origin,
        $ip,
        $reason,
      ]);
      $groupCounts[$groupKey] = [
        'host' => $host,
        'client' => $client,
        'mcp_client' => $mcpClient,
        'origin' => $origin,
        'ip' => $ip,
        'reason' => $reason,
        'count' => McpStoredValue::int($groupCounts[$groupKey]['count'] ?? 0) + 1,
      ];
    }

    return [
      'scanned' => $scanned,
      'sources' => $this->sourceRows($this->topMaps($sourceCounts, $topN)),
      'reasons' => $this->topPairs($reasonCounts, $topN),
      'tenants' => $this->topPairs($tenantCounts, $topN),
      'groups' => $this->groupRows($this->topMaps($groupCounts, $topN)),
    ];
  }

  /**
   * Site identity plus bounded grouping for one fired rule.
   *
   * Shared by the email renderer and the audit/webhook metadata so a
   * dispatch scans matching rows once.
   *
   * @param array<string, mixed> $item
   *   Detector result with `rule` and `count`.
   *
   * @return \Drupal\mcp_sentinel\Value\McpAnomalyPreparedRule
   *   Identity and summary for this fired rule.
   */
  public function prepareFiredRule(array $item): McpAnomalyPreparedRule {
    $rule = [];
    $rawRule = $item['rule'] ?? NULL;
    if (is_array($rawRule)) {
      foreach ($rawRule as $key => $value) {
        if (is_string($key)) {
          $rule[$key] = $value;
        }
      }
    }
    $window = McpStoredValue::int($item['window'] ?? $rule['window_seconds'] ?? 0);
    $pattern = McpStoredValue::string($rule['operation_pattern'] ?? '');
    $signal = McpStoredValue::string($item['signal'] ?? $rule['signal'] ?? 'count');
    $since = $this->time->getRequestTime() - max($window, 0);
    $summary = $pattern !== '' && $window > 0
      ? $this->summarize($pattern, $since, $signal, $rule)
      : $this->emptySummary();
    return new McpAnomalyPreparedRule(
      $rule,
      McpStoredValue::int($item['count'] ?? 0),
      $window,
      McpStoredValue::int($item['threshold'] ?? $rule['threshold'] ?? 0),
      $signal !== '' ? $signal : 'count',
      $this->siteIdentity(),
      $summary,
    );
  }

  /**
   * Plain-text body for one fired rule. Never includes secrets.
   *
   * @param \Drupal\mcp_sentinel\Value\McpAnomalyPreparedRule $prepared
   *   Result of prepareFiredRule().
   *
   * @return string
   *   Bounded multi-line body. Every enrichment field is always present.
   */
  public function renderAlertBody(McpAnomalyPreparedRule $prepared): string {
    $rule = $prepared->rule;
    $count = $prepared->count;
    $window = $prepared->window;
    $threshold = $prepared->threshold;
    $ruleLabel = McpStoredValue::string($rule['label'] ?? $rule['id'] ?? 'unknown');
    if ($ruleLabel === '') {
      $ruleLabel = 'unknown';
    }
    $summary = $prepared->summary;
    $identity = $prepared->identity;
    $lines = [
      sprintf(
        'Rule "%s" triggered: %d operations in %d s (threshold %d).',
        $ruleLabel,
        $count,
        $window,
        $threshold,
      ),
      '',
      'Site: ' . $identity['site'],
      'Host: ' . $identity['host'],
      'Environment: ' . $identity['environment'],
      'Window: ' . $window . ' s',
      'Threshold: ' . $threshold,
      '',
      'Top sources (max ' . self::TOP_N . '):',
    ];
    if ($summary['sources'] === []) {
      $lines[] = '- ' . self::MISSING;
    }
    else {
      foreach ($summary['sources'] as $source) {
        $lines[] = sprintf(
          '- client=%s mcp_client=%s (self-reported) origin=%s host=%s ip=%s principal=%s count=%d',
          $source['client'],
          $source['mcp_client'],
          $source['origin'],
          $source['host'],
          $source['ip'],
          $source['principal'],
          $source['count'],
        );
      }
    }
    $lines[] = '';
    $lines[] = 'Reason codes:';
    $this->appendPairs($lines, $summary['reasons']);
    $lines[] = '';
    $lines[] = 'Tenants:';
    $this->appendPairs($lines, $summary['tenants']);
    return implode("\n", $lines);
  }

  /**
   * Denied-access grouping for the operator Drush command.
   *
   * @param int $windowSeconds
   *   Lookback window in seconds.
   * @param int $topN
   *   Maximum groups to return.
   *
   * @return array{site: array{site: string, host: string, environment: string}, window_seconds: int, count: int, scanned: int, truncated: bool, groups: list<array{host: string, client: string, mcp_client: string, origin: string, ip: string, reason: string, count: int}>}
   *   Identity plus bounded groups. Count is the un-capped match
   *   total; scanned is the number of rows decrypted. No tokens or
   *   payloads.
   */
  public function deniedAccessSummary(int $windowSeconds, int $topN = self::TOP_N): array {
    $since = $this->time->getRequestTime() - $windowSeconds;
    $count = McpAuditOperationQuery::countMatching(
      $this->database,
      'denied_access',
      $since,
    );
    $summary = $this->summarize('denied_access', $since, 'count', [], $topN);
    return [
      'site' => $this->siteIdentity(),
      'window_seconds' => $windowSeconds,
      'count' => $count,
      'scanned' => $summary['scanned'],
      'truncated' => $count > $summary['scanned'],
      'groups' => $summary['groups'],
    ];
  }

  /**
   * Records that an operator read the denied-access summary.
   *
   * Fail-closed: callers must not print the summary if this throws.
   *
   * @param int $windowSeconds
   *   Lookback window that was queried.
   * @param int $count
   *   Matching row count (un-capped).
   * @param int $groups
   *   Number of groups returned.
   * @param string $outcome
   *   Read, or a refusal reason such as invalid_window or invalid_top.
   */
  public function auditOperatorSummary(
    int $windowSeconds,
    int $count,
    int $groups,
    string $outcome = 'read',
  ): void {
    $this->auditLogger->logAlways(self::AUDIT_DENIED_ACCESS_SUMMARY, [
      'window_seconds' => $windowSeconds,
      'count' => $count,
      'groups' => $groups,
      'outcome' => $this->label($outcome),
    ]);
  }

  /**
   * Bounded evidence map to store on the anomaly_alert audit row.
   *
   * @param \Drupal\mcp_sentinel\Value\McpAnomalyPreparedRule $prepared
   *   Result of prepareFiredRule().
   *
   * @return array{site: string, host: string, environment: string, sources: list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>, reasons: array<string, int>, tenants: array<string, int>}
   *   Allowlisted identity and counts. No payloads.
   */
  public function boundedAlertMetadata(McpAnomalyPreparedRule $prepared): array {
    $identity = $prepared->identity;
    $summary = $prepared->summary;
    return [
      'site' => $identity['site'],
      'host' => $identity['host'],
      'environment' => $identity['environment'],
      'sources' => $summary['sources'],
      'reasons' => $summary['reasons'],
      'tenants' => $summary['tenants'],
    ];
  }

  /**
   * Absolute host URL for this process, or `(none)`.
   */
  private function hostUrl(): string {
    $request = $this->requestStack->getCurrentRequest();
    if ($request !== NULL) {
      $host = $request->getSchemeAndHttpHost();
      if ($host !== '') {
        return $this->label($host);
      }
    }
    try {
      return $this->label(Url::fromRoute('<front>', [], [
        'absolute' => TRUE,
      ])->toString());
    }
    catch (\Throwable) {
      return self::MISSING;
    }
  }

  /**
   * First present allowlisted metadata label, or `(none)`.
   *
   * @param array<string, mixed> $meta
   *   Decoded metadata.
   * @param list<string> $keys
   *   Keys to try in order.
   */
  private function firstLabel(array $meta, array $keys): string {
    foreach ($keys as $key) {
      if (!isset($meta[$key])) {
        continue;
      }
      $label = $this->label($meta[$key]);
      if ($label !== self::MISSING) {
        return $label;
      }
    }
    return self::MISSING;
  }

  /**
   * Bounded, redacted label. Never returns a secret or empty string.
   */
  private function label(mixed $value): string {
    if (!is_scalar($value) || is_bool($value)) {
      return self::MISSING;
    }
    $text = mb_scrub((string) $value, 'UTF-8');
    $stripped = preg_replace('/\p{Cc}/u', '', $text);
    if (is_string($stripped)) {
      $text = $stripped;
    }
    $text = trim($text);
    if ($text === '') {
      return self::MISSING;
    }
    $text = $this->redactSecrets($text);
    $text = $this->dlp->scan($text);
    $text = mb_strcut($text, 0, self::LABEL_MAX, 'UTF-8');
    $text = trim($text);
    return $text === '' ? self::MISSING : $text;
  }

  /**
   * Redacts auth schemes, JWTs, URL userinfo, and query tokens.
   */
  private function redactSecrets(string $text): string {
    $patterns = [
      '/(Bearer|Basic|Digest|Token|ApiKey|Negotiate)\s+\S+/i' => '$1 [REDACTED]',
      '/eyJ[\w-]+\.[\w-]+\.[\w-]+/' => '[REDACTED]',
      '/((?:access_token|id_token|refresh_token|token|code|key|sig|signature|password)=)[^&\s]+/i' => '$1[REDACTED]',
      '#//[^/\s]+@#' => '//[REDACTED]@',
    ];
    foreach ($patterns as $pattern => $replacement) {
      $redacted = preg_replace($pattern, $replacement, $text);
      if (is_string($redacted)) {
        $text = $redacted;
      }
    }
    return $text;
  }

  /**
   * Typed source rows after ranking.
   *
   * @param list<array<string, mixed>> $rows
   *   Ranked maps.
   *
   * @return list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>
   *   Allowlisted source fields only.
   */
  private function sourceRows(array $rows): array {
    $out = [];
    foreach ($rows as $row) {
      $out[] = [
        'client' => McpStoredValue::string($row['client'] ?? ''),
        'mcp_client' => McpStoredValue::string($row['mcp_client'] ?? ''),
        'principal' => McpStoredValue::string($row['principal'] ?? ''),
        'origin' => McpStoredValue::string($row['origin'] ?? ''),
        'host' => McpStoredValue::string($row['host'] ?? ''),
        'ip' => McpStoredValue::string($row['ip'] ?? ''),
        'count' => McpStoredValue::int($row['count'] ?? 0),
      ];
    }
    return $out;
  }

  /**
   * Typed group rows after ranking.
   *
   * @param list<array<string, mixed>> $rows
   *   Ranked maps.
   *
   * @return list<array{host: string, client: string, mcp_client: string, origin: string, ip: string, reason: string, count: int}>
   *   Allowlisted group fields only.
   */
  private function groupRows(array $rows): array {
    $out = [];
    foreach ($rows as $row) {
      $out[] = [
        'host' => McpStoredValue::string($row['host'] ?? ''),
        'client' => McpStoredValue::string($row['client'] ?? ''),
        'mcp_client' => McpStoredValue::string($row['mcp_client'] ?? ''),
        'origin' => McpStoredValue::string($row['origin'] ?? ''),
        'ip' => McpStoredValue::string($row['ip'] ?? ''),
        'reason' => McpStoredValue::string($row['reason'] ?? ''),
        'count' => McpStoredValue::int($row['count'] ?? 0),
      ];
    }
    return $out;
  }

  /**
   * Highest-count maps first, capped at $topN.
   *
   * @param array<string, array<string, mixed>> $items
   *   Map of grouping key => row with a `count` int.
   * @param int $topN
   *   Cap.
   *
   * @return list<array<string, mixed>>
   *   Sorted rows. Ties break by a stable label of the row fields.
   */
  private function topMaps(array $items, int $topN): array {
    uasort($items, static function (array $a, array $b): int {
      $byCount = McpStoredValue::int($b['count'] ?? 0)
        <=> McpStoredValue::int($a['count'] ?? 0);
      if ($byCount !== 0) {
        return $byCount;
      }
      return self::mapTieLabel($a) <=> self::mapTieLabel($b);
    });
    return array_values(array_slice($items, 0, $topN));
  }

  /**
   * Stable label used to tie-break equal counts.
   *
   * @param array<string, mixed> $row
   *   One grouping row.
   */
  private static function mapTieLabel(array $row): string {
    $copy = $row;
    unset($copy['count']);
    ksort($copy);
    $parts = [];
    foreach ($copy as $value) {
      $parts[] = McpStoredValue::string($value);
    }
    return implode("\0", $parts);
  }

  /**
   * Highest-count string=>int pairs first, capped at $topN.
   *
   * @param array<string, int> $counts
   *   Label => count.
   * @param int $topN
   *   Cap.
   *
   * @return array<string, int>
   *   Sorted, capped map.
   */
  private function topPairs(array $counts, int $topN): array {
    arsort($counts);
    return array_slice($counts, 0, $topN, TRUE);
  }

  /**
   * Appends `- label: count` lines, or a missing placeholder.
   *
   * @param list<string> $lines
   *   Body lines, modified in place.
   * @param array<string, int> $pairs
   *   Label => count.
   */
  private function appendPairs(array &$lines, array $pairs): void {
    if ($pairs === []) {
      $lines[] = '- ' . self::MISSING;
      return;
    }
    foreach ($pairs as $label => $count) {
      $lines[] = '- ' . $label . ': ' . $count;
    }
  }

  /**
   * Empty grouping used when a rule has no pattern or window.
   *
   * @return array{scanned: int, sources: list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>, reasons: array<string, int>, tenants: array<string, int>, groups: list<array{host: string, client: string, mcp_client: string, origin: string, ip: string, reason: string, count: int}>}
   *   Zeroed summary.
   */
  private function emptySummary(): array {
    return [
      'scanned' => 0,
      'sources' => [],
      'reasons' => [],
      'tenants' => [],
      'groups' => [],
    ];
  }

}
