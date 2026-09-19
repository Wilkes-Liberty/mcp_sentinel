<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpAnomalyDetector;
use Drupal\mcp_sentinel\Service\McpUrgentConditions;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports urgent conditions and anomaly findings as codes and counts.
 *
 * Messages, URLs and actor ids from the backing services are dropped.
 */
#[Tool(
  id: 'mcp_sentinel_urgent_conditions',
  label: new TranslatableMarkup('Urgent conditions'),
  description: new TranslatableMarkup('Report urgent governance conditions and fired anomaly rules as codes and counts. No messages, URLs, secrets or personal data.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class McpUrgentConditionsTool extends McpStatusToolBase {

  /**
   * Urgent conditions.
   */
  protected McpUrgentConditions $urgent;

  /**
   * Anomaly detector.
   */
  protected McpAnomalyDetector $anomalies;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->urgent = $container->get('mcp_sentinel.urgent_conditions');
    $instance->anomalies = $container->get('mcp_sentinel.anomaly_detector');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $conditions = [];
    foreach ($this->urgent->evaluate() as $condition) {
      $key = $condition['key'];
      if ($key === '') {
        continue;
      }
      $conditions[] = [
        'key' => $key,
        'severity' => $condition['severity'],
      ];
    }
    $anomalies = [];
    foreach ($this->anomalies->evaluate() as $fired) {
      $rule = is_array($fired['rule'] ?? NULL) ? $fired['rule'] : [];
      $id = (string) ($rule['id'] ?? '');
      if ($id === '') {
        continue;
      }
      $anomalies[] = [
        'id' => $id,
        'signal' => (string) ($fired['signal'] ?? ''),
        'count' => (int) ($fired['count'] ?? 0),
        'window' => (int) ($fired['window'] ?? 0),
        'threshold' => (int) ($fired['threshold'] ?? 0),
      ];
    }
    return [
      'conditions' => $conditions,
      'anomalies' => $anomalies,
    ];
  }

}
