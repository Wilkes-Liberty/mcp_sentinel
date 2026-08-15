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
  case Drush = 'drush';

  /**
   * Whether the surface is intrinsically a Sentinel product path.
   *
   * Tool, Context and the governed drush SQL command exist only because
   * Sentinel provides them; JSON:API and GraphQL are site APIs the module
   * governs when the request is on the agent channel.
   */
  public function isDedicated(): bool {
    return $this === self::Tool || $this === self::Context || $this === self::Drush;
  }

  /**
   * Maps a request path to its API surface, or NULL when out of scope.
   *
   * Matches by segment rather than prefix so language-prefixed paths
   * (/en/jsonapi/...) resolve too. Only the two HTTP API surfaces are
   * path-addressable; Tool and Context requests are identified by their
   * routes, and Drush has no request at all, so none of those resolve here.
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
