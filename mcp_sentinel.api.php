<?php

/**
 * @file
 * Hooks invoked by MCP Sentinel.
 */

/**
 * Operator-decision hook when a two-person confirmer does not respond.
 *
 * DEV-985: an unconfirmed person-wide or tenant-wide freeze stays
 * frozen when the confirm window ends. This hook notifies the named
 * second person and the break-glass path. Implementations must not
 * lift the freeze or complete a pending un-kill. There is no timeout
 * that promotes the request to a single-operator action.
 *
 * @param array $context
 *   Keys: batch_id, transition ('kill' or 'unkill'), first_operator_id
 *   (account id, never a username), selector_type, selector_key. No
 *   tokens.
 */
function hook_mcp_sentinel_kill_unavailable_confirmer(array $context): void {
  // Notify the named second person and the break-glass operator.
  // Do not lift the freeze.
}
