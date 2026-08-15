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

  /**
   * Maps a request path to its API surface, or NULL when out of scope.
   *
   * Matches by segment rather than prefix so language-prefixed paths
   * (/en/jsonapi/...) resolve too. Only the two HTTP API surfaces are
   * path-addressable; Tool and Context requests are identified by their
   * routes, not here.
   *
   * @param string $path
   *   The request path (Request::getPathInfo()).
   */
  public static function fromPath(string $path): ?self {
    if (str_contains($path, '/jsonapi/')) {
      return self::JsonApi;
    }
    if (str_contains($path, '/graphql')) {
      return self::Graphql;
    }
    return NULL;
  }

}
