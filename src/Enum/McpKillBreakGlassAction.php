<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Enum;

/**
 * Break-glass actions on an unconfirmed mass freeze.
 *
 * Keep, extend, and lift still require a distinct verified operator.
 * The action is audited as break-glass use, not as a silent skip of
 * the two-person rule.
 */
enum McpKillBreakGlassAction: string {

  case Keep = 'keep';
  case Extend = 'extend';
  case Lift = 'lift';

}
