# MCP Sentinel

## Introduction

Enterprise security presets, audit logging, content locks, and HMAC webhooks
for MCP-connected Drupal sites.

MCP Sentinel is the governance control plane that sits in front of AI-agent
access to Drupal over the Model Context Protocol (MCP), JSON:API, and GraphQL:
it decides what an agent may touch, redacts what it must not see, records what it
did, and protects content humans are editing. It is an ecosystem module for
[MCP Server](https://www.drupal.org/project/mcp_server) and the
[Tool API](https://www.drupal.org/project/tool).

## Trust model

Governance triggers on the **authenticated account's roles**, never on a request
header. A request is "governed" when its user holds one of the configured
*governed roles* (default: the `mcp_api` role created on install) or a role bound
to a policy profile. The `X-MCP-Client` header is at most a log hint — an agent
cannot bypass policy by omitting it, and a non-agent user cannot be governed by
adding it. The `anonymous` and `authenticated` roles can never be governed.

Each governed agent is matched to an **`mcp_policy_profile`** (the highest-weight
enabled profile whose roles it holds, else the shipped `default` profile), which
defines its operation gates, entity allow/deny lists, and redacted fields. Manage
profiles at **Configuration → Web services → MCP Sentinel → MCP policy profiles**.

## Requirements

- Drupal 10.3+ or 11
- [Tool API](https://www.drupal.org/project/tool) (`drupal/tool`)
- [Key](https://www.drupal.org/project/key) (`drupal/key`) — stores the webhook
  signing secret outside exported configuration
- **Strongly recommended:** [MCP Server](https://www.drupal.org/project/mcp_server),
  [Simple OAuth](https://www.drupal.org/project/simple_oauth)

## Installation

```bash
composer require drupal/mcp_sentinel drupal/mcp_server drupal/simple_oauth

# Enable the base module plus the mcp_server integration submodule.
drush en mcp_sentinel mcp_sentinel_server mcp_server_tool_bridge -y
drush cr

# Register the MCP Sentinel Tool plugins with mcp_server.
drush mcp-sentinel:setup
```

> **mcp_server 2.x requires a patch to `mcp/sdk`.** It adds the runtime element
> handler interfaces (`RuntimeToolHandlerInterface` et al.) that the Tool bridge
> depends on; without it, tool discovery fails. The patch ships inside the
> mcp_server project at
> `web/modules/contrib/mcp_server/.gitlab-ci/patches/mcp-sdk-runtime-handlers.patch`.
> Register it with `cweagans/composer-patches` for the `mcp/sdk` package and
> reinstall/repatch (`composer patches-relock && composer patches-repatch` for
> composer-patches v2).

## Submodules

| Submodule | Purpose |
|-----------|---------|
| `mcp_sentinel_server` | Registers the Tool plugins with mcp_server (`mcp_tool_config` entities) and wires OAuth scopes. Provides `drush mcp-sentinel:setup` / `:teardown`. Depends on `mcp_server_tool_bridge`. |
| `mcp_sentinel_graphql` | Extends governance to the GraphQL endpoint: gates mutations/reads, redacts fields, and audits operations for governed agents. Depends on `graphql_compose`. |

### GraphQL governance (`mcp_sentinel_graphql`)

For governed agents — requests whose authenticated account holds a governed role
(see [Trust model](#trust-model); never a request header):

- **Mutations** are blocked unless the agent's policy profile allows both write
  and GraphQL mutations; **reads** are blocked when the profile disallows read;
  all GraphQL access is blocked when MCP access is disabled. Non-governed traffic
  (the site's own GraphQL consumers) is untouched.
- **Redacted fields** are replaced with `[REDACTED]`. The core `user.roles`
  cache context keeps agent and public responses cached separately, so redacted
  values never leak across the boundary.
- **Operations are audited** to the MCP Sentinel audit log (queries honour the
  *Log read operations* setting; mutations are always logged). Gating and audit
  apply on cache hits too, so the response cache cannot be used to bypass policy.
- **Entity allow/deny lists** already apply to GraphQL reads through Drupal's
  entity access system (no extra configuration needed).

A `mcp_sentinel_graphql_schema` tool exposes the GraphQL SDL so agents can
discover available types, queries, and mutations.

## What This Adds

| Feature | Without module | With module |
|---------|:-:|:-:|
| JSON:API access | ✅ | ✅ |
| Security presets (read-only, auditor, etc.) | ❌ | ✅ |
| Entity type allow/deny lists | ❌ | ✅ |
| Field-level PII redaction | ❌ | ✅ |
| Audit log | ❌ | ✅ |
| Content locks | ❌ | ✅ |
| HMAC webhooks | ❌ | ✅ |
| Rich context endpoint | ❌ | ✅ |
| mcp_api role | ❌ | ✅ |

## Configuration

**Configuration → Web services → MCP Sentinel** (`/admin/config/services/mcp-sentinel`)

## Companion Node.js Connector

[drupal-mcp-server](https://github.com/wilkes-liberty/drupal-mcp-server) —
external MCP connector with 66 tools, multi-site, GraphQL, and Drush bridge.

## Maintainers

- Wilkes & Liberty — [drupal.org/u/wilkes-liberty](https://www.drupal.org/u/wilkes-liberty)

See `MAINTAINERS.txt`. Report issues and feature requests in the
[project issue queue](https://www.drupal.org/project/issues/mcp_sentinel); report
sensitive security issues to the Drupal security team at security@drupal.org.
