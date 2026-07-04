<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_server;

use Drupal\tool\Tool\ToolOperation;

/**
 * Derives the OAuth scope a Sentinel tool requires from its own declarations.
 *
 * The scope is a function of two facts the tool plugin already declares: its
 * ToolOperation (read vs modifying, via ToolOperation::isModifying()) and
 * whether it operates on configuration (declared by implementing
 * ConfigScopeToolInterface). This makes the plugin the single source of truth
 * for its scope, replacing a hand-maintained per-tool table that could drift
 * from the plugin's declared operation.
 *
 * Scope grid:
 * - content + read  => mcp_read
 * - content + write => mcp_write
 * - config  + read  => mcp_config_read
 * - config  + write => mcp_config
 *
 * The config write scope keeps the legacy name 'mcp_config' (rather than a
 * symmetric 'mcp_config_write') so existing developer/admin-tier tokens and the
 * shipped oauth2_scope entity continue to work unchanged.
 */
final class ToolScopeResolver {

  /**
   * Resolves the OAuth scope machine id for a tool.
   *
   * @param \Drupal\tool\Tool\ToolOperation $operation
   *   The tool's declared operation.
   * @param bool $isConfigDomain
   *   TRUE if the tool operates on configuration (config-domain scope).
   *
   * @return string
   *   The OAuth scope machine id the tool must require.
   */
  public static function resolve(ToolOperation $operation, bool $isConfigDomain): string {
    $modifying = $operation->isModifying();
    if ($isConfigDomain) {
      return $modifying ? 'mcp_config' : 'mcp_config_read';
    }
    return $modifying ? 'mcp_write' : 'mcp_read';
  }

}
