# Changelog

All notable changes to MCP Sentinel are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
stable release is tagged.

## [Unreleased]

### Fixed
- **DLP fail-open on PCRE runtime error:** `McpDlp::replaceMatches()` now
  detects a NULL return from `preg_replace`/`preg_replace_callback` (e.g. on
  a backtrack-limit hit) and returns the **original value unchanged** instead of
  silently coercing NULL to `''`. A warning is logged to the `mcp_sentinel`
  channel. Previously a PCRE error would blank the field value.
- **DLP partial mode fully masks short matches:** in partial masking mode, a
  match whose length is ≤ 4 characters (equal to `PARTIAL_KEEP`) is now
  **fully replaced with `*` characters** instead of being returned verbatim.
  The previous behaviour exposed the entire matched value — e.g. a 4-digit PIN
  matched by a custom pattern would pass through unmasked. Matches longer than
  4 characters are unaffected (last-4 semantics preserved).
- **DLP custom-pattern UI (spec T6.1):** the settings form now exposes a
  *Custom DLP patterns* textarea in the DLP fieldset. Operators enter one
  pattern per line as `label|regex|mask` (mask is optional). The form validates
  each regex using `McpDlp::wrapPattern()` before saving and rejects malformed
  lines with a clear error message. Saving an empty textarea clears to `[]` and
  falls back to the built-in defaults at runtime. A new `McpDlp::wrapPattern()`
  public static helper ensures the form and the service always agree on the
  exact delimiter convention.
- **DLP `us_phone` regex matches no-separator format:** `(555)123-4567`
  (closing area-code paren with no following space or separator) was previously
  not matched. The separator after `)` is now optional (`[\s.\-]?`).

### Added
- **Approval-workflow submodule (`mcp_sentinel_approval`, optional):** an
  opt-in human-approval gate for governed destructive operations. When enabled,
  the base bulk-operations tool dispatches a veto-capable `McpDestructiveOpEvent`
  before each delete; the submodule's subscriber queues a pending
  `mcp_approval_request` content entity and vetoes execution, so the target is
  left intact and reported to the agent as *queued for approval*. Operators with
  the new **Approve MCP Sentinel operations** permission review the queue at
  `/admin/reports/mcp-sentinel/approvals` and approve or deny requests; approving
  replays the stored operation (re-checking the approver's delete access) and
  writes an `approval_decision` audit row. Gated operations are configurable
  (`gated_operations`, default `[delete]`). The base module has no dependency on
  the submodule — when it is absent the event is never vetoed and destructive
  operations proceed unchanged.
- **DLP value-pattern redaction + partial masking (opt-in):** a new
  `McpDlp` service scans governed field values against configurable PII
  patterns (email, US phone, SSN, 16-digit credit card, plus unlimited
  site-defined custom patterns) and either fully redacts matches
  (`[REDACTED]`) or applies partial masking (last-4 chars kept, rest
  replaced with `*`). Scanning is **off by default** (`dlp_enabled: false`);
  enable and configure under *Configuration → Web services → MCP Sentinel →
  Data Loss Prevention*. `update_10005` adds the three new settings to
  existing installs.
  - **V1 wired output paths:** (a) GraphQL Compose field output (via
    `mcp_sentinel_graphql_graphql_compose_field_results_alter` in the
    `mcp_sentinel_graphql` submodule) and (b) the audit change-diff capture
    (`McpAuditLogger::computeChangeDiff`). JSON:API/REST per-value scanning
    is deferred to a future release (no stable per-value normalizer alter
    hook exists in Drupal core).
  - **Regex convention:** patterns store the PCRE body WITHOUT delimiters
    (e.g. `[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`). The service wraps
    each pattern in `#...#i` delimiters at runtime. Invalid patterns are
    silently skipped with a warning logged to the `mcp_sentinel` channel.

### Security
- **Optional at-rest encryption of audit metadata:** when `audit_encryption_profile`
  is set to an Encryption Profile entity ID (from drupal/encrypt), the `metadata`
  column of every new audit row is encrypted at rest. Reads transparently decrypt
  via the `decodeMetadata()` accessor with graceful fallback to plain JSON for
  pre-encryption rows, so no data migration is required when enabling encryption
  on an existing install. The hash chain continues to hash plaintext canonical
  content (encryption only affects storage), so `drush mcp-sentinel:audit-verify`
  remains reliable across key rotations. drupal/encrypt is now a required
  dependency.
- **HMAC-keyed audit hash chain:** the audit hash chain now uses
  HMAC-SHA256 when `audit_hash_key` is set to a Key entity ID (plain SHA-256
  is retained as a zero-config fallback). Set the key to a File or Environment
  provider so the signing secret never appears in exported configuration.
  `update_10004` adds the `audit_hash_key` setting to existing installs.
- **Tamper-evident audit log (hash chain):** every audit row now stores a
  `prev_hash` (the preceding row's hash) and `row_hash` (HMAC-SHA256 or
  SHA-256 of `prev_hash | canonical-JSON`). Any insertion, deletion, or
  modification of a historical row breaks the chain; run
  `drush mcp-sentinel:audit-verify` to detect it. `update_10003` adds the two
  columns to existing installs.
- **Full-column canonical:** the audit chain canonical now includes
  `entity_label`, `ip_address`, and `user_agent` in fixed key order, so
  post-hoc alteration of forensic columns also breaks the chain.
- **Serialized chain writes:** the read-latest-then-insert critical section
  in the audit logger is protected by Drupal's lock service to prevent
  hash-chain races under concurrent writes.
- MCP governance triggers on the **validated OAuth agent channel**
  (consumer/scope on the request's access token), not on role alone. An admin's
  direct cookie-session Drupal UI is never governed; only token-bearing agent
  traffic is governed and audited.
- Per-tool `mcp:read`/`mcp:write` scope enforcement is now active via
  `mcp_server_oauth` third-party settings on each `mcp_tool_config`. Run
  `drush mcp-sentinel:setup --require-oauth` to apply.
- Governed redaction and entity-access decisions vary by both `user.roles` and
  `oauth2_scopes` cache contexts, preventing agent-channel responses from being
  served to cookie-session requests for the same user.
- Governance now triggers on the agent's **authenticated roles** as a
  configurable local-dev fallback (`governed_role_fallback`, default `false`),
  not the spoofable `X-MCP-Client` header. An agent cannot bypass policy by
  omitting the header; a non-agent user cannot be governed by adding it.
- The HMAC webhook signing secret is now resolved from a **Key** entity
  (`webhook_secret_key`) instead of being stored as plaintext in exported
  configuration. `update_10001` migrates any existing plaintext secret into a
  Key. drupal/key is now a required dependency.
- The `/drupal-mcp/context` endpoint no longer discloses the Drupal version.

### Fixed
- `allow_read` is now enforced on JSON:API/REST reads (the `view` operation was
  previously ungated outside GraphQL).
- `McpContentLock::isLocked()` no longer writes (deletes expired rows) on every
  read; expired locks are excluded by a query condition and reaped by cron.
- Uninstalling the module now removes the `mcp_api` role it creates on install.

### Added
- **SIEM streaming via a dedicated logger channel:** when the new *Enable SIEM
  streaming* setting (`siem_enabled`) is turned on, every successful audit write
  also emits an `info`-level record to the dedicated `mcp_sentinel_audit`
  logger channel. The message is the stable string `mcp_sentinel_audit_event`
  (suitable for log-aggregator grouping); all variable data is in a structured
  context array: `operation`, `uid`, `entity_type`, `bundle`, `entity_id`,
  `timestamp`, `row_hash`. Route the channel to syslog (via the core Syslog
  module or Monolog) to stream structured audit events to a SIEM without
  database polling. See the README for configuration details.
- **Filterable audit log UI with CSV/JSON export:** the
  `/admin/reports/mcp-sentinel` listing now exposes a GET-based filter form
  (operation, entity type, UID, date range). A new
  `/admin/reports/mcp-sentinel/export` route (permission
  `view mcp sentinel audit log`) streams the filtered log as a CSV download by
  default or a JSON array when `?format=json` is requested. All metadata reads
  in the controller flow through `McpAuditLogger::decodeMetadata()` — the
  accessor seam that Feature 5 will swap to transparently decrypt.
- **Redaction-aware change diffs in the audit log:** governed entity updates now
  include a `changes` map (`{field: {old, new}}`) in the audit metadata,
  capturing exactly what changed. Fields listed in the resolved policy profile's
  `redacted_fields` are stored as `[REDACTED]` (both old and new values), so
  sensitive field values never appear in the audit trail. Unchanged fields and
  internal revision-bookkeeping fields are omitted. Values are capped at 255
  characters and at most 50 fields are recorded per event.
- `McpOauthContext` service (`mcp_sentinel.oauth_context`) — reads the
  server-validated OAuth agent channel (consumer `client_id` + token scopes)
  for the current request. Single seam between MCP Sentinel and simple_oauth.
- `agent_oauth_clients`, `agent_scopes`, `governed_role_fallback` settings in
  `mcp_sentinel.settings` (schema + install defaults). Controls the OAuth
  channel detection; role fallback defaults to `false`.
- `docs/CONNECTOR.md` — the connector ↔ Drupal contract: grant type, token
  endpoint, per-environment Consumer + scopes + TTL runbook, agent policy
  profile values, and end-to-end verification procedure.
- `drush mcp-sentinel:status` now shows the OAuth agent-channel config row
  (`agent_oauth_clients`, `agent_scopes`, `governed_role_fallback`).
- `mcp_policy_profile` config entity for per-agent governance policy (operation
  gates, entity allow/deny lists, field redaction, role bindings, weight).
  Resolved by role with a `default` profile fallback; `update_10002` migrates
  existing flat settings. Full admin UI at
  `/admin/config/services/mcp-sentinel/profiles`.
- `McpPolicyResolver` service: `isGoverned(account)` and `resolve(account)` —
  OAuth-channel-primary governance detection and role-based profile resolution
  with deterministic highest-weight tie-break.
- Governed Tool API plugins: site context, security policy, content lock, node
  create/update, media create, workflow transition, and bulk operations.
- `mcp_sentinel_server` submodule — registers the Tool plugins with `mcp_server`
  and wires per-tool OAuth scopes (`drush mcp-sentinel:setup` / `:teardown`).
- `mcp_sentinel_graphql` submodule — mutation/read gating, field redaction, and
  audit for the GraphQL Compose endpoint, plus a GraphQL SDL discovery tool.
- Field-level redaction unified across JSON:API/REST (stripped) and GraphQL
  (`[REDACTED]`) via `hook_entity_field_access` and the `user.roles` +
  `oauth2_scopes` cache contexts.
- Base Drush commands: `mcp-sentinel:status`, `:audit-purge`, `:lock-clear`,
  `:audit-verify` (verifies the hash chain; exits non-zero if broken).
- `phpcs.xml.dist`, `phpstan.neon.dist` (level 6), and unit/kernel/functional
  test coverage.

### Notes
- Pre-1.0 and in active development. See `ROADMAP.md` for the enterprise
  hardening plan and current status.

## [1.0.0-initial] - 2026

### Added
- Initial release: security presets, audit logging, content locks, HMAC
  webhooks, the `/drupal-mcp/context` and `/drupal-mcp/health` endpoints, and the
  `mcp_api` role.
