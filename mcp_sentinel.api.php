<?php

/**
 * @file
 * Hooks invoked by MCP Sentinel.
 */

/**
 * Operator-decision hook when a two-person confirmer does not respond.
 *
 * @todo DEV-846 operator decision: the unavailable-confirmer rule is
 *   not decided. Implementations must not apply a pending mass kill or
 *   complete a pending un-kill. There is no timeout that promotes the
 *   request to a single-operator action and no break-glass skip. Until
 *   the operator decides, the pending request expires with the confirm
 *   window and the two-person rule holds.
 *
 * @param array $context
 *   Keys: batch_id, transition ('kill' or 'unkill'), first_operator_id
 *   (account id, never a username), selector_type, selector_key. No
 *   tokens.
 */
function hook_mcp_sentinel_kill_unavailable_confirmer(array $context): void {
  // Record that the named second person (secondary account holder) did
  // not confirm. Do not weaken the two-person rule.
}
