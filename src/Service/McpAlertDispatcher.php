<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Language\LanguageManagerInterface;
use Drupal\Core\Mail\MailManagerInterface;
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
 * every rule result it receives without additional suppression.
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
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly LoggerInterface $sentinelLogger,
    private readonly MailManagerInterface $mailManager,
    private readonly McpWebhookQueueManager $webhookQueueManager,
    private readonly LanguageManagerInterface $languageManager,
    private readonly McpAuditLogger $auditLogger,
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
      $count = (int) $item['count'];
      $ruleLabel = (string) ($rule['label'] ?? $rule['id'] ?? 'unknown');
      $ruleId = (string) ($rule['id'] ?? '');
      $window = (int) ($item['window'] ?? $rule['window_seconds'] ?? 0);
      $threshold = (int) ($item['threshold'] ?? $rule['threshold'] ?? 0);
      $evidence = $this->boundedEvidence($item, $rule, $count, $window, $threshold);
      $this->auditLogger->log('anomaly_alert', $evidence);

      $message = sprintf(
        'Rule "%s" triggered: %d operations in %d s (threshold %d).',
        $ruleLabel,
        $count,
        $window,
        $threshold,
      );

      // Log channel alert.
      if ($alertLog) {
        $this->sentinelLogger->warning(
          'mcp_sentinel_anomaly_alert @rule: @message',
          [
            '@rule'    => $ruleId,
            '@message' => $message,
            'count'    => $count,
            'rule'     => $rule,
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
            'body'    => $message,
            'rule'    => $rule,
            'count'   => $count,
          ],
        );
      }

      // Webhook alert: enqueue via the F9 queue manager with the
      // 'mcp.anomaly.alert' event name so configured endpoints whose
      // 'events' filter includes 'mcp.anomaly.alert' receive it.
      if ($alertWebhook) {
        $this->webhookQueueManager->enqueueForEvent('mcp.anomaly.alert', [
          'rule_id'        => $ruleId,
          'rule_label'     => $ruleLabel,
          'count'          => $count,
          'threshold'      => $threshold,
          'window_seconds' => $window,
          'signal'         => $evidence['signal'],
          'actor'          => $evidence['actor'],
          'target_scope'   => $evidence['target_scope'],
          'rule_version'   => $evidence['rule_version'],
          'outcome'        => $evidence['outcome'],
          'timestamp'      => time(),
        ]);
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
   *
   * @return array{signal: string, actor: list<int>, target_scope: list<string>, rule_version: string, window: int, threshold: int, outcome: string, rule_id: string, count: int}
   *   Audit metadata — no credentials or payload.
   */
  private function boundedEvidence(array $item, array $rule, int $count, int $window, int $threshold): array {
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
    ];
  }

}
