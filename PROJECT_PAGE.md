# MCP Sentinel

**Enterprise governance for Drupal sites exposed to AI agents over the Model
Context Protocol (MCP).**

AI agents and MCP clients can now read and write Drupal content through
[MCP Server](https://www.drupal.org/project/mcp_server), JSON:API, and GraphQL.
MCP Sentinel is the control plane that sits in front of that access: it decides
*what* an agent may touch, *redacts* what it must not see, *records* everything
it does, and *protects* content humans are actively editing — without you having
to reimplement transport or authentication.

It builds **on top of** the Acquia-sponsored, Lullabot-maintained
`mcp_server` module and the shared **Tool API** (`drupal/tool`). MCP Sentinel
does not reinvent the MCP protocol, OAuth, or the tool plugin system — it adds
the governance layer those projects intentionally leave to site builders.

## What it does

- **Security presets & operation gates** — master on/off switch plus
  independent read / write / delete / GraphQL-mutation toggles. When disabled,
  MCP requests are refused regardless of credentials.
- **Entity-type allow / deny lists** — restrict agents to an allowlist of
  entity types, or block sensitive ones (users are denied by default). Enforced
  through Drupal's own access system, so JSON:API and GraphQL reads honour it
  automatically.
- **Field-level redaction** — name fields (e.g. `mail`, `pass`) that are hidden
  from MCP requests: stripped from JSON:API/REST output and returned as
  `[REDACTED]` in GraphQL. A dedicated cache context keeps agent and public
  responses cached separately, so redacted data never leaks across the boundary.
- **Audit logging** — every MCP entity operation and GraphQL query/mutation is
  written to a dedicated, query-optimised log with user, IP, timestamp, and
  payload metadata. Configurable retention with automatic pruning. The admin
  listing is filterable (operation, entity type, UID, date range) and exports
  to CSV or JSON.
- **Tamper-evident audit hash chain** — every audit row is chained with a
  `prev_hash`/`row_hash` (HMAC-SHA256 when keyed via a Key entity, SHA-256
  otherwise); `drush mcp-sentinel:audit-verify` detects any insertion,
  deletion, or modification of historical rows.
- **Redaction-aware change diffs** — governed updates record exactly which
  fields changed (`{field: {old, new}}`); redacted fields are stored as
  `[REDACTED]` so sensitive values never enter the audit trail.
- **At-rest audit encryption** — optionally encrypt the audit `metadata` column
  via a drupal/encrypt Encryption Profile; reads decrypt transparently.
- **SIEM streaming** — optionally emit each audit write to a dedicated
  `mcp_sentinel_audit` logger channel for forwarding to a SIEM via Syslog or
  Monolog.
- **DLP value-pattern redaction (opt-in)** — scan governed field values for PII
  patterns (email, US phone, SSN, credit card, plus custom patterns) and fully
  redact or partially mask matches.
- **Content locks** — prevent agents from overwriting content a human is
  editing, with TTL-based expiry.
- **HMAC-signed webhooks** — fire HTTPS-only, HMAC-SHA256-signed notifications
  to your own systems on MCP-driven entity changes.
- **Rich context endpoint** — `/drupal-mcp/context` exposes a full site schema
  (content types with fields, vocabularies, media types) so agents can discover
  your model before acting; `/drupal-mcp/health` provides a status probe.
- **Governed Tool plugins** — ready-to-use Tool API tools (site context,
  security policy, content locks, node create/update, media creation, workflow
  transitions, bulk publish/unpublish/delete, GraphQL schema discovery), each
  routed through the same policy, access, and content-lock checks.

## Submodules

- **MCP Sentinel Server** (`mcp_sentinel_server`) — registers the Tool plugins
  with `mcp_server` and wires per-tool OAuth scopes. Provides
  `drush mcp-sentinel:setup` to auto-register every tool.
- **MCP Sentinel GraphQL** (`mcp_sentinel_graphql`) — extends governance to the
  GraphQL Compose endpoint: gates mutations and reads, audits operations, and
  applies field redaction for MCP requests.
- **MCP Sentinel Approval** (`mcp_sentinel_approval`) — optional human-approval
  gate: queues governed destructive operations (bulk delete) as approval
  requests for an authorized human to approve or deny instead of executing
  them immediately.

## Requirements

- Drupal 10.3+ or 11
- [Tool API](https://www.drupal.org/project/tool) (`drupal/tool`)
- [Key](https://www.drupal.org/project/key) (`drupal/key`) — stores the webhook
  signing secret (and optional audit encryption key) outside exported config
- [Simple OAuth](https://www.drupal.org/project/simple_oauth) (`drupal/simple_oauth`)
  and [Consumers](https://www.drupal.org/project/consumers) (`drupal/consumers`) —
  the validated OAuth agent channel governance triggers on
- [Encrypt](https://www.drupal.org/project/encrypt) (`drupal/encrypt`) —
  Encryption Profiles for optional at-rest encryption of audit metadata
- **Strongly recommended:** [MCP Server](https://www.drupal.org/project/mcp_server)
  (exposes the tools to MCP clients)
- **Optional:** [GraphQL Compose](https://www.drupal.org/project/graphql_compose)
  for the GraphQL governance submodule

The security, audit, content-lock, redaction, and webhook features all work even
without `mcp_server` installed.

## Quick start

```bash
composer require drupal/mcp_sentinel drupal/mcp_server drupal/simple_oauth
drush en mcp_sentinel mcp_sentinel_server mcp_server_tool_bridge -y
drush mcp-sentinel:setup
```

Configure at **Configuration → Web services → MCP Sentinel**
(`/admin/config/services/mcp-sentinel`). Review activity at
**Reports → MCP Sentinel Audit Log**.

## Drush

- `drush mcp-sentinel:status` — show the active policy plus audit/lock counts
- `drush mcp-sentinel:setup` — register all tools with `mcp_server`
- `drush mcp-sentinel:audit-purge` — prune audit entries past retention
- `drush mcp-sentinel:lock-clear` — release expired content locks
- `drush mcp-sentinel:audit-verify` — verify the tamper-evident audit hash chain

## Companion connector

[drupal-mcp-server](https://github.com/wilkes-liberty/drupal-mcp-server) is an
external Node.js MCP connector (multi-site, JSON:API + GraphQL, Drush bridge)
that pairs with MCP Sentinel; the module identifies its requests automatically.

## Security

Covered by Drupal's security advisory policy. Report issues through the project
issue queue (or security@drupal.org for sensitive reports).
