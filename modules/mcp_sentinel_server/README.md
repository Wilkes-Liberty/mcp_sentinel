# MCP Sentinel Server

Bridges the MCP Sentinel Tool plugins to the [MCP Server](https://www.drupal.org/project/mcp)
module so an MCP client can call them, and provisions the per-environment agent
tiers.

This submodule has **no settings page** — it is operated entirely through Drush.
See its help at `/admin/help/mcp_sentinel_server` and the project
[`README.md`](../../README.md) / [`API.md`](../../API.md) for the full picture.

## What it does

- Registers each Sentinel tool as an `mcp_tool_config` entity so `mcp_server`
  exposes it.
- Requires `mcp_server_oauth` on production setup, then tags each tool with the OAuth scope
  **derived from the tool plugin itself** (content read/write vs config
  read/write), so a content-tier token can never reach the config tools.
- Provisions agent tiers (role + service account + designated OAuth Consumer)
  without creating or rotating secrets.
- Participates in the shared `/drupal-mcp/readiness` source-contract check;
  missing server/bridge/OAuth/tool/identity/policy/audit wiring denies every
  governed product path rather than falling back to plain Drupal.

## Requirements

- `mcp_sentinel` (parent)
- `mcp_server` and its `mcp_server_tool_bridge` (to expose the tools)
- `mcp_server_oauth` (required for production readiness)

## Usage

```bash
# Register the Sentinel tools with required OAuth scopes (the default).
drush mcp-sentinel:setup

# Provision an agent tier as a role + service account + OAuth consumer.
# Tiers: content, content-auditor, auditor, developer, admin.
drush mcp-sentinel:agent-provision content --env=prod

# Remove the tool registrations.
drush mcp-sentinel:teardown
```

Consumer secrets are **never** created or rotated by these commands — set them
out of band.

For a deliberately unauthenticated local-only experiment,
`drush mcp-sentinel:setup --allow-unauthenticated-development` writes disabled
authentication settings, returns non-zero, and leaves production readiness
false. There is no implicit or successful unauthenticated setup mode.
