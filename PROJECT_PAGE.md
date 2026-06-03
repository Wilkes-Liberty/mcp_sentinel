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

**How governance triggers.** MCP Sentinel governs traffic on the validated
**OAuth agent channel** — a designated consumer, or an agent scope on the
request's access token (server-validated, never a spoofable header). Your public
frontend and your own cookie-session admin work are unaffected. The acting
agent's **role selects the policy profile**, and every governed action is
attributed to the authenticated account.

## What it does

- **Per-role policy profiles** — every gate, redaction rule, rate limit, quota
  cap, and IP allowlist lives on a reusable policy-profile config entity; the
  acting agent's Drupal role selects which profile applies, so different agents
  can have different policies.
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
- **Governance dashboard** — a read-only operations console at
  `/admin/reports/mcp-sentinel` with an urgent-conditions banner, a posture
  rollup, status tiles, a chain-integrity card, top-agents and denied-by-policy
  panels, charts, quick actions, and an active-controls strip — all built from
  data the module already stores.
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
- **Per-profile rate limiting & quotas** — throttle governed agent traffic with
  Drupal's core flood service (max requests per rolling window), keyed on the
  server-resolved user ID so a single compromised token cannot saturate the
  server. `0` = unlimited.
- **Exfiltration guards** — cap how much data a governed agent can pull in one
  call: a per-profile result-item cap (Tool output, JSON:API `page[limit]`, and
  GraphQL multi-value field lists) and a response-size cap on Tool output. Blocks
  mass-read and accidental data exfiltration.
- **Per-profile IP allowlisting** — restrict governed connections to specific
  IPv4/IPv6 addresses and CIDR blocks. Trusted-proxy-aware (reads the real client
  IP via Symfony, never a spoofable header) and enforced across entity access,
  the governed Tool plugins, and the context endpoint. Empty list = no
  restriction.
- **Anomaly detection & alerting** — cron-evaluated rules over the audit log
  (operation pattern, time window, count threshold) that fire alerts via log,
  email, or webhook channels, with per-rule debounce to prevent alert storms.
  Includes governed `denied_access` auditing as a detection signal. Ships with no
  rules enabled.
- **Content locks** — prevent agents from overwriting content a human is
  editing, with TTL-based expiry.
- **Reliable webhooks** — queue-backed, HTTPS-only, HMAC-SHA256-signed delivery
  to multiple endpoints with per-event filtering, retry with exponential backoff,
  a two-layer SSRF guard, and a delivery log with one-click replay.
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
(`/admin/config/services/mcp-sentinel`). Review activity at the governance
dashboard, **Reports → MCP Sentinel** (`/admin/reports/mcp-sentinel`), with the
filterable audit log on its **Audit log** tab.

## Drush

- `drush mcp-sentinel:status` — show the active policy plus audit/lock counts
- `drush mcp-sentinel:setup` — register all tools with `mcp_server`
- `drush mcp-sentinel:audit-purge` — prune audit entries past retention
- `drush mcp-sentinel:lock-clear` — release expired content locks
- `drush mcp-sentinel:audit-verify` — verify the tamper-evident audit hash chain
- `drush mcp-sentinel:webhook-replay <id>` — re-queue a webhook delivery
- `drush mcp-sentinel:webhook-prune` — prune webhook delivery rows past retention

## Companion connector

[drupal-mcp-connector](https://github.com/Wilkes-Liberty/drupal-mcp-connector) is an
external Node.js MCP connector (multi-site, JSON:API + GraphQL, Drush bridge)
that pairs with MCP Sentinel; the module records its `X-MCP-Client` label in the
audit log. MCP Sentinel implements the shared **Integration Contract v1.0**
(compatibility: mcp_sentinel ≥ 1.0 ↔ drupal-mcp-connector ≥ 0.6).

## Security

Covered by Drupal's security advisory policy. Report issues through the project
issue queue (or security@drupal.org for sensitive reports).
