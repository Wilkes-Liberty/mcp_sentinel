<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpMetrics;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports audit counts for fixed windows. Never names an agent.
 */
#[Tool(
  id: 'mcp_sentinel_audit_metrics',
  label: new TranslatableMarkup('Audit metrics'),
  description: new TranslatableMarkup('Report audit totals, allowed against denied, denial reasons, operation mix and webhook health for 24h, 7d and 30d. Does not name agents. No secrets or personal data.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class McpAuditMetricsTool extends McpStatusToolBase {

  /**
   * Windows this tool always returns.
   */
  private const WINDOWS = ['24h', '7d', '30d'];

  /**
   * Metrics service.
   */
  protected McpMetrics $metrics;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->metrics = $container->get('mcp_sentinel.metrics');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $windows = [];
    foreach (self::WINDOWS as $window) {
      $windows[$window] = [
        'counts' => $this->metrics->auditCounts($window),
        'allowed_vs_denied' => $this->metrics->allowedVsDenied($window),
        'denied_reasons' => $this->metrics->deniedReasons($window),
        'operation_mix' => $this->metrics->operationMix($window),
        'webhook_health' => $this->metrics->webhookHealth($window),
      ];
    }
    return ['windows' => $windows];
  }

}
