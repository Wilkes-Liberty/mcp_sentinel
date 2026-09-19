<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports source-governance contract status as a ready flag and reason code.
 *
 * The governed base still applies the readiness gate on this tool. When the
 * request itself is not ready, the caller gets the standard not-ready refusal
 * which already names the reason code. When the request is ready (including
 * the development role-fallback used in tests), this returns the
 * connector-facing contract status, which can still be not ready.
 */
#[Tool(
  id: 'mcp_sentinel_governance_status',
  label: new TranslatableMarkup('Governance status'),
  description: new TranslatableMarkup('Report whether MCP Sentinel source governance is ready, and the reason code when it is not. No secrets or personal data.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class McpGovernanceStatusTool extends McpStatusToolBase {

  /**
   * Source-governance contract.
   */
  protected McpGovernanceReadiness $readiness;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->readiness = $container->get('mcp_sentinel.governance_readiness');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $status = $this->readiness->contractStatus();
    return [
      'ready' => $status->isReady(),
      'reason' => $status->reason()?->value,
    ];
  }

}
