<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Draft;

/**
 * HTTP header names for MCP draft continuation.
 *
 * Held here so services that stamp audit metadata can read the names
 * without importing the JSON:API draft controller.
 */
final class McpDraftHeaders {

  /**
   * Header that selects create (omitted) or revise.
   */
  public const MODE_HEADER = 'X-MCP-Draft-Mode';

  /**
   * Header that selects the translation to create, read, or continue.
   */
  public const LANGCODE_HEADER = 'X-MCP-Draft-Langcode';

}
