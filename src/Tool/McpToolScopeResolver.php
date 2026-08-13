<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Tool;

use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\Tool\ToolDefinition;

/**
 * Derives exact OAuth scopes from each Tool plugin's own declarations.
 */
final class McpToolScopeResolver {

  /**
   * Always-required Sentinel Tool IDs.
   */
  public const REQUIRED_TOOLS = [
    'mcp_sentinel_site_context',
    'mcp_sentinel_security_policy',
    'mcp_sentinel_content_lock',
    'mcp_sentinel_node_operations',
    'mcp_sentinel_media_create',
    'mcp_sentinel_workflow_transition',
    'mcp_sentinel_bulk_operations',
    'mcp_sentinel_config_get',
    'mcp_sentinel_config_list',
    'mcp_sentinel_config_set',
  ];

  /**
   * Optional Tool IDs, checked only when their plugin is compiled.
   */
  public const OPTIONAL_TOOLS = ['mcp_sentinel_graphql_schema'];

  /**
   * Resolves the exact scope for one Tool operation/domain.
   */
  public static function resolve(
    ToolOperation $operation,
    bool $isConfigDomain,
  ): string {
    if ($isConfigDomain) {
      return $operation->isModifying() ? 'mcp_config' : 'mcp_config_read';
    }
    return $operation->isModifying() ? 'mcp_write' : 'mcp_read';
  }

  /**
   * Resolves the exact scope from one discovered Tool definition.
   */
  public static function resolveDefinition(ToolDefinition $definition): string {
    return self::resolve(
      $definition->getOperation(),
      is_a($definition->getClass(), ConfigScopeToolInterface::class, TRUE),
    );
  }

}
