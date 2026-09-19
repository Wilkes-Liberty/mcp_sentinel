<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpReadBudgetResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports the acting profile's effective result, size, rate and page budgets.
 */
#[Tool(
  id: 'mcp_sentinel_effective_limits',
  label: new TranslatableMarkup('Effective limits'),
  description: new TranslatableMarkup('Report the effective result cap, response-size cap, rate limit and page budget for the acting governance profile. No secrets or personal data.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class McpEffectiveLimitsTool extends McpStatusToolBase {

  /**
   * Read-budget resolver.
   */
  protected McpReadBudgetResolver $budgets;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->budgets = $container->get('mcp_sentinel.read_budgets');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
    if ($profile === NULL) {
      throw new \InvalidArgumentException('No profile.');
    }
    [$requests, $requestWindow] = $this->budgets->effectiveRateLimit($profile);
    [$pages, $pageWindow] = $this->budgets->pageBudget();
    return [
      'result_cap' => $this->budgets->effectiveResultCap($profile),
      'response_size_cap' => $this->budgets->effectiveResponseSizeCap($profile),
      'rate_limit_requests' => $requests,
      'rate_limit_window' => $requestWindow,
      'page_budget' => $pages,
      'page_window' => $pageWindow,
    ];
  }

}
