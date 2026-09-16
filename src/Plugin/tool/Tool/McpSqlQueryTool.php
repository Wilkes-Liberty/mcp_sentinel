<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpGovernedSql;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Runs bounded SELECT queries under the authenticated account's own policy.
 */
#[Tool(
  id: 'mcp_sentinel_sql_query',
  label: new TranslatableMarkup('Governed SELECT query'),
  description: new TranslatableMarkup('Run a single bounded SELECT statement. Requires explicit raw SQL permission in the authenticated account policy; no caller-selected profile or database fallback.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'query' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('SELECT statement'),
      description: new TranslatableMarkup('A single SELECT statement, at most 8192 bytes.'),
      required: TRUE,
    ),
  ],
)]
final class McpSqlQueryTool extends McpGovernedToolBase {

  /**
   * Shared governed SQL execution pipeline.
   */
  protected McpGovernedSql $governedSql;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->governedSql = $container->get('mcp_sentinel.governed_sql');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedAccess(array $values, AccountInterface $account): AccessResultInterface {
    $profile = $this->governancePolicyResolver?->resolve($account);
    return AccessResult::allowedIf($profile !== NULL && $profile->status() && $profile->allowsRawSql())->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    try {
      // Direct PHP execution must not bypass discovery/invoker access checks.
      if (!$this->checkAccess($values, $this->currentUser) || array_diff(array_keys($values), ['query'])) {
        return ExecutableResult::failure($this->t('Governed SQL access refused.'));
      }
      $profile = $this->governancePolicyResolver->resolve($this->currentUser);
      $result = $this->governedSql->run($values['query'], $profile, McpGovernedSurface::Tool);
      return ExecutableResult::success($this->t('Governed SELECT completed.'), $result);
    }
    catch (\Throwable $exception) {
      // SQL, returned values, guard details and driver errors stay out of chat.
      return ExecutableResult::failure($this->t('Governed SQL refused. Check policy, statement, budgets and audit availability.'));
    }
  }

}
