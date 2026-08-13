<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\tool\Tool\ToolBase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Enforces the non-bypassable readiness gate for Sentinel Tool plugins.
 */
abstract class McpGovernedToolBase extends ToolBase {

  /**
   * Source-governance readiness service.
   */
  protected McpGovernanceReadiness $governanceReadiness;

  /**
   * IP allowlist and policy access checker.
   */
  protected McpAccessChecker $governanceAccessChecker;

  /**
   * Exact OAuth scope derived from this plugin's declaration.
   */
  protected string $governanceRequiredScope;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->governanceReadiness = $container->get('mcp_sentinel.governance_readiness');
    $instance->governanceAccessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->governanceRequiredScope = McpToolScopeResolver::resolveDefinition($plugin_definition);
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  final protected function checkAccess(
    array $values,
    AccountInterface $account,
    bool $return_as_object = FALSE,
  ): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission(
      $account,
      'access mcp sentinel context',
    );
    if (!$access->isAllowed()) {
      return $return_as_object ? $access : FALSE;
    }

    $readiness = $this->governanceReadiness->evaluate(
      McpGovernedSurface::Tool,
      $account,
      $this->governanceRequiredScope,
    );
    if (!$readiness->isReady()) {
      $reason = $readiness->reason()->value;
      $denied = AccessResult::forbidden(
        'MCP Sentinel source governance is not ready: ' . $reason . '.',
      )->addCacheableDependency($readiness);
      return $return_as_object ? $denied : FALSE;
    }

    $profile = $readiness->profile();
    if ($profile === NULL || !$this->governanceAccessChecker->isClientIpAllowed($profile)) {
      $denied = AccessResult::forbidden(
        'Source IP not permitted by MCP Sentinel policy.',
      )->setCacheMaxAge(0);
      return $return_as_object ? $denied : FALSE;
    }

    $subclassAccess = $this->checkGovernedAccess($values, $account);
    $access->addCacheableDependency($readiness);
    $access = $access->andIf($subclassAccess);
    return $return_as_object ? $access : $access->isAllowed();
  }

  /**
   * Applies optional Tool-specific access after the common governance gates.
   *
   * Subclasses may narrow the decision but cannot bypass permission,
   * readiness, or IP policy because the public access seam above is final.
   */
  protected function checkGovernedAccess(
    array $values,
    AccountInterface $account,
  ): AccessResultInterface {
    return AccessResult::allowed();
  }

}
