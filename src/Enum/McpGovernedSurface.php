<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Source-of-record surfaces governed by MCP Sentinel.
 */
enum McpGovernedSurface: string {

  case Tool = 'tool';
  case Context = 'context';
  case JsonApi = 'jsonapi';
  case Graphql = 'graphql';

  /**
   * Whether the surface is intrinsically a Sentinel product path.
   */
  public function isDedicated(): bool {
    return $this === self::Tool || $this === self::Context;
  }

}
