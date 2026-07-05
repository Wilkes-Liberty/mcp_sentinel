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
- When `mcp_server_oauth` is enabled, tags each tool with the OAuth scope
  **derived from the tool plugin itself** (content read/write vs config
  read/write), so a content-tier token can never reach the config tools.
- Provisions agent tiers (role + service account + OAuth consumer).

## Requirements

- `mcp_sentinel` (parent)
- `mcp_server` and its `mcp_server_tool_bridge` (to expose the tools)
- `mcp_server_oauth` (optional, to require OAuth scopes)

## Usage

```bash
# Register the Sentinel tools with mcp_server (and require OAuth scopes).
drush mcp-sentinel:setup --require-oauth

# Provision an agent tier as a role + service account + OAuth consumer.
# Tiers: content, content-auditor, auditor, developer, admin.
drush mcp-sentinel:agent-provision content --env=prod

# Remove the tool registrations.
drush mcp-sentinel:teardown
```

Consumer secrets are **never** created or rotated by these commands — set them
out of band.
