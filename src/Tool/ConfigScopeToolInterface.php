<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Tool;

/**
 * Marks a tool as operating on configuration rather than content.
 *
 * The OAuth scope a Sentinel tool requires is derived from two facts the tool
 * declares about itself: its ToolOperation (read vs modifying) and whether it
 * is config-domain. A tool implementing this interface is config-domain, so its
 * scope comes from the config family (mcp_config_read for non-modifying
 * operations, mcp_config for modifying) instead of the content family
 * (mcp_read / mcp_write). This keeps the plugin the single source of truth for
 * its scope; the derivation lives in
 * \Drupal\mcp_sentinel_server\ToolScopeResolver.
 */
interface ConfigScopeToolInterface {}
