<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Mail\MailManagerInterface;
use Drupal\mcp_sentinel\McpWebhookEvents;
use Drupal\mcp_sentinel\Value\McpAnomalyPreparedRule;
use Psr\Log\LoggerInterface;

/**
 * Dispatches anomaly alerts through configured channels (log, email, webhook).
 *
 * Alert channels are selected globally via settings:
 *   - anomaly_alert_log (boolean): write a warning to the mcp_sentinel logger.
 *   - anomaly_alert_email (string): send an email if non-empty; empty = skip.
 *   - anomaly_alert_webhook (boolean): enqueue via the F9 webhook queue
 *     manager.
 *
 * Debounce is handled upstream in McpAnomalyDetector; this dispatcher fires for
 * every rule result it receives without additional suppression. Every channel
 * carries the same bounded site/host/source/reason/tenant evidence; the email
 * body is the triage document. Enrichment failures never suppress an alert:
 * the headline is still sent on every channel.
 */
final class McpAlertDispatcher {

  /**
   * Constructs a new McpAlertDispatcher.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory.
   * @param \Psr\Log\LoggerInterface $sentinelLogger
   *   The mcp_sentinel logger channel.
   * @param \Drupal\Core\Mail\MailManagerInterface $mailManager
   *   The mail manager.
   * @param \Drupal\mcp_sentinel\Service\McpWebhookQueueManager $webhookQueueManager
   *   The F9 webhook queue manager (for enqueuing webhook alerts).
   * @param \Drupal\Core\Language\LanguageManagerInterface $languageManager
   *   The language manager (for mail langcode).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   Writes the bounded anomaly_alert evidence row.
   * @param \Drupal\mcp_sentinel\Service\McpAnomalyEvidence $anomalyEvidence
   *   Builds the bounded triage body and metadata for every fired rule.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $sentinelLogger,
    private readonly MailManagerInterface $mailManager,
    private readonly McpWebhookQueueManager $webhookQueueManager,
    private readonly LanguageManagerInterface $languageManager,
    private readonly McpAuditLogger $auditLogger,
    private readonly McpAnomalyEvidence $anomalyEvidence,
  ) {}

  /**
   * Dispatches alerts for a set of fired anomaly rules.
   *
   * @param array $firedRules
   *   Array of fired rule results from McpAnomalyDetector::evaluate().
   *   Each element should be an array with keys 'rule' (array) and
   *   'count' (int). Malformed entries are silently skipped.
   */
  public function dispatch(array $firedRules): void {
    if (!$firedRules) {
      return;
    }
    $config = $this->configFactory->get('mcp_sentinel.settings');
    $alertLog = (bool) $config->get('anomaly_alert_log');
    $alertEmail = trim((string) ($config->get('anomaly_alert_email') ?? ''));
    $alertWebhook = (bool) $config->get('anomaly_alert_webhook');

    foreach ($firedRules as $item) {
      if (!is_array($item) || !isset($item['rule'], $item['count'])) {
        continue;
      }
      $rule = $item['rule'];
      if (!is_array($rule)) {
        continue;
      }
      $count = (int) $item['count'];
      $ruleLabel = (string) ($rule['label'] ?? $rule['id'] ?? 'unknown');
      $ruleId = (string) ($rule['id'] ?? '');
      $window = (int) ($item['window'] ?? $rule['window_seconds'] ?? 0);
      $threshold = (int) ($item['threshold'] ?? $rule['threshold'] ?? 0);
      $headline = sprintf(
        'Rule "%s" triggered: %d operations in %d s (threshold %d).',
        $ruleLabel,
        $count,
        $window,
        $threshold,
      );
      $body = $headline;
      $identity = [
        'site' => McpAnomalyEvidence::MISSING,
        'host' => McpAnomalyEvidence::MISSING,
        'environment' => McpAnomalyEvidence::ENV_UNSET,
      ];
      try {
        $prepared = $this->anomalyEvidence->prepareFiredRule($item);
        $identity = $prepared->identity;
        if ($alertEmail !== '') {
          $body = $this->anomalyEvidence->renderAlertBody($prepared);
        }
        $evidence = $this->boundedEvidence(
          $item,
          $rule,
          $count,
          $window,
          $threshold,
          $prepared,
        );
      }
      catch (\Throwable $e) {
        $this->sentinelLogger->error(
          'Anomaly alert enrichment failed for @rule: @class. Sending headline only.',
          [
            '@rule' => $ruleId,
            '@class' => $this->exceptionShortClass($e),
            'exception' => $e,
          ],
        );
        try {
          $identity = $this->anomalyEvidence->siteIdentity();
        }
        catch (\Throwable) {
          // Identity stays at the missing placeholders.
        }
        $body = $headline . "\nTriage details unavailable ("
          . $this->exceptionShortClass($e) . ')';
        $evidence = $this->fallbackEvidence(
          $item,
          $rule,
          $count,
          $window,
          $threshold,
          $identity,
        );
      }
      $this->auditLogger->log('anomaly_alert', $evidence);

      // Log channel alert. Identity is in the PSR-3 context so a syslog
      // line still names the site without dumping the full email body.
      if ($alertLog) {
        $this->sentinelLogger->warning(
          'mcp_sentinel_anomaly_alert @rule: @message',
          [
            '@rule' => $ruleId,
            '@message' => $headline,
            'count' => $count,
            'rule' => $rule,
            'site' => $identity['site'],
            'host' => $identity['host'],
            'environment' => $identity['environment'],
          ],
        );
      }

      // Email alert: only when a non-empty address is configured.
      if ($alertEmail !== '') {
        $langcode = $this->languageManager->getDefaultLanguage()->getId();
        $this->mailManager->mail(
          'mcp_sentinel',
          'anomaly_alert',
          $alertEmail,
          $langcode,
          [
            'subject' => 'MCP Sentinel anomaly: ' . $ruleLabel,
            'body' => $body,
            'rule' => $rule,
            'count' => $count,
          ],
        );
      }

      // Webhook alert: enqueue via the F9 queue manager with
      // McpWebhookEvents::ANOMALY_ALERT so configured endpoints whose
      // events filter includes that live name receive it.
      if ($alertWebhook) {
        $this->webhookQueueManager->enqueueForEvent(
          McpWebhookEvents::ANOMALY_ALERT,
          [
            'rule_id' => $ruleId,
            'rule_label' => $ruleLabel,
            'count' => $count,
            'threshold' => $threshold,
            'window_seconds' => $window,
            'signal' => $evidence['signal'],
            'actor' => $evidence['actor'],
            'target_scope' => $evidence['target_scope'],
            'rule_version' => $evidence['rule_version'],
            'outcome' => $evidence['outcome'],
            'site' => $evidence['site'],
            'host' => $evidence['host'],
            'environment' => $evidence['environment'],
            'sources' => $evidence['sources'],
            'reasons' => $evidence['reasons'],
            'tenants' => $evidence['tenants'],
            'timestamp' => time(),
          ],
        );
      }
    }
  }

  /**
   * Bounded, non-sensitive evidence for one fired rule.
   *
   * @param array<string, mixed> $item
   *   The detector result.
   * @param array<string, mixed> $rule
   *   The rule map.
   * @param int $count
   *   Matching-row count that tripped the rule.
   * @param int $window
   *   Lookback window in seconds.
   * @param int $threshold
   *   Configured threshold.
   * @param \Drupal\mcp_sentinel\Value\McpAnomalyPreparedRule $prepared
   *   Result of McpAnomalyEvidence::prepareFiredRule().
   *
   * @return array{signal: string, actor: list<int>, target_scope: list<string>, rule_version: string, window: int, threshold: int, outcome: string, rule_id: string, count: int, site: string, host: string, environment: string, sources: list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>, reasons: array<string, int>, tenants: array<string, int>}
   *   Audit metadata — no credentials or payload.
   */
  private function boundedEvidence(
    array $item,
    array $rule,
    int $count,
    int $window,
    int $threshold,
    McpAnomalyPreparedRule $prepared,
  ): array {
    $meta = $this->anomalyEvidence->boundedAlertMetadata($prepared);
    $actor = $item['actor'] ?? [];
    $scope = $item['target_scope'] ?? [];
    return [
      'signal' => (string) ($item['signal'] ?? $rule['signal'] ?? 'count'),
      'actor' => is_array($actor) ? array_values(array_map('intval', $actor)) : [],
      'target_scope' => is_array($scope) ? array_values(array_map('strval', $scope)) : [],
      'rule_version' => (string) ($item['rule_version'] ?? McpAnomalyDetector::ruleVersion($rule)),
      'window' => $window,
      'threshold' => $threshold,
      'outcome' => (string) ($item['outcome'] ?? 'fired'),
      'rule_id' => (string) ($rule['id'] ?? ''),
      'count' => $count,
      'site' => $meta['site'],
      'host' => $meta['host'],
      'environment' => $meta['environment'],
      'sources' => $meta['sources'],
      'reasons' => $meta['reasons'],
      'tenants' => $meta['tenants'],
    ];
  }

  /**
   * Headline-only evidence when enrichment throws.
   *
   * @param array<string, mixed> $item
   *   The detector result.
   * @param array<string, mixed> $rule
   *   The rule map.
   * @param int $count
   *   Matching-row count that tripped the rule.
   * @param int $window
   *   Lookback window in seconds.
   * @param int $threshold
   *   Configured threshold.
   * @param array{site: string, host: string, environment: string} $identity
   *   Best-effort site identity.
   *
   * @return array{signal: string, actor: list<int>, target_scope: list<string>, rule_version: string, window: int, threshold: int, outcome: string, rule_id: string, count: int, site: string, host: string, environment: string, sources: list<array{client: string, mcp_client: string, principal: string, origin: string, host: string, ip: string, count: int}>, reasons: array<string, int>, tenants: array<string, int>}
   *   Audit metadata — no credentials or payload.
   */
  private function fallbackEvidence(
    array $item,
    array $rule,
    int $count,
    int $window,
    int $threshold,
    array $identity,
  ): array {
    $actor = $item['actor'] ?? [];
    $scope = $item['target_scope'] ?? [];
    return [
      'signal' => (string) ($item['signal'] ?? $rule['signal'] ?? 'count'),
      'actor' => is_array($actor) ? array_values(array_map('intval', $actor)) : [],
      'target_scope' => is_array($scope) ? array_values(array_map('strval', $scope)) : [],
      'rule_version' => (string) ($item['rule_version'] ?? McpAnomalyDetector::ruleVersion($rule)),
      'window' => $window,
      'threshold' => $threshold,
      'outcome' => (string) ($item['outcome'] ?? 'fired'),
      'rule_id' => (string) ($rule['id'] ?? ''),
      'count' => $count,
      'site' => $identity['site'],
      'host' => $identity['host'],
      'environment' => $identity['environment'],
      'sources' => [],
      'reasons' => [],
      'tenants' => [],
    ];
  }

  /**
   * Unqualified class name of a throwable.
   */
  private function exceptionShortClass(\Throwable $e): string {
    $class = $e::class;
    $pos = strrpos($class, '\\');
    return $pos === FALSE ? $class : substr($class, $pos + 1);
  }

}
