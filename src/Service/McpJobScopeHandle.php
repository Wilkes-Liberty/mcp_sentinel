<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

/**
 * Opaque handle returned by enterJobScope().
 *
 * The matching leaveJobScope() accepts only the instance
 * enterJobScope() returned. A newly constructed handle is
 * refused.
 *
 * @internal
 */
final class McpJobScopeHandle {

}
