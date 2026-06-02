# Changelog

All notable changes to MCP Sentinel are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project will
adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
stable release is tagged.

## [Unreleased]

### Added
- **Per-profile rate limiting & quotas via core flood:** each `mcp_policy_profile`
  now carries `rate_limit_requests` and `rate_limit_window` fields (integers,
  default `0` = unlimited). When non-zero, the `McpRateLimiter` service
  (`mcp_sentinel.rate_limiter`) enforces the limit using Drupal's core `@flood`
  service. The flood key is `mcp_sentinel.profile.{profile_id}.{uid}` — keyed
  on the server-resolved authenticated UID only, preventing key-cycling bypass
  attacks. A `0` limit short-circuits before touching flood. Enforcement is
  wired at the top of all four governed Tool plugins: `mcp_sentinel_node_operations`,
  `mcp_sentinel_bulk_operations`, `mcp_sentinel_media_create`, and
  `mcp_sentinel_workflow_transition`. Over-limit calls log an audit row with
  operation `rate_limit_exceeded` and return a failure result equivalent to
  HTTP 429. The profile add/edit form gains a *Rate limits* fieldset with the
  two new fields. `update_10006` backfills the fields (and future F8b cap
  fields `result_count_cap`, `response_size_cap`) on existing profiles.
  Recommended prod starting point: 300 requests / 60 s window.
- **Tamper-evident audit log with HMAC hash chain + `audit-verify`:** every
  audit row stores a `prev_hash` (the preceding row's hash) and `row_hash`
  (HMAC-SHA256 of `prev_hash | canonical-JSON` when `audit_hash_key` is set to a
  Key entity ID, plain SHA-256 as a zero-config fallback). Any insertion,
  deletion, or modification of a historical row breaks the chain; run
  `drush mcp-sentinel:audit-verify` to detect it (exits non-zero if broken). The
  canonical includes the forensic columns `entity_label`, `ip_address`, and
  `user_agent` in fixed key order, and the read-latest-then-insert critical
  section is serialized via Drupal's lock service to prevent races under
  concurrent writes. `update_10003` adds the two columns; `update_10004` adds the
  `audit_hash_key` setting.
- **Redaction-aware change diffs in the audit log:** governed entity updates now
  include a `changes` map (`{field: {old, new}}`) in the audit metadata,
  capturing exactly what changed. Fields listed in the resolved policy profile's
  `redacted_fields` are stored as `[REDACTED]` (both old and new values), so
  sensitive field values never appear in the audit trail. Unchanged fields and
  internal revision-bookkeeping fields are omitted. Values are capped at 255
  characters and at most 50 fields are recorded per event.
- **Filterable audit log UI with CSV/JSON export:** the
  `/admin/reports/mcp-sentinel` listing now exposes a GET-based filter form
  (operation, entity type, UID, date range). A new
  `/admin/reports/mcp-sentinel/export` route (permission
  `view mcp sentinel audit log`) streams the filtered log as a CSV download by
  default or a JSON array when `?format=json` is requested. All metadata reads
  in the controller flow through `McpAuditLogger::decodeMetadata()`, the accessor
  seam that transparently decrypts at-rest-encrypted rows.
- **SIEM streaming via a dedicated logger channel:** when the *Enable SIEM
  streaming* setting (`siem_enabled`) is turned on, every successful audit write
  also emits an `info`-level record to the dedicated `mcp_sentinel_audit`
  logger channel. The message is the stable string `mcp_sentinel_audit_event`
  (suitable for log-aggregator grouping); all variable data is in a structured
  context array: `operation`, `uid`, `entity_type`, `bundle`, `entity_id`,
  `timestamp`, `row_hash`. Route the channel to syslog (via the core Syslog
  module or Monolog) to stream structured audit events to a SIEM without
  database polling. See the README for configuration details.
- **DLP value-pattern redaction + partial masking (opt-in):** a new
  `McpDlp` service scans governed field values against configurable PII
  patterns (email, US phone, SSN, 16-digit credit card, plus unlimited
  site-defined custom patterns) and either fully redacts matches
  (`[REDACTED]`) or applies partial masking (last-4 chars kept, rest
  replaced with `*`). Scanning is **off by default** (`dlp_enabled: false`);
  enable and configure under *Configuration → Web services → MCP Sentinel →
  Data Loss Prevention*, including a *Custom DLP patterns* textarea
  (`label|regex|mask` per line, validated on save). `update_10005` adds the new
  settings to existing installs.
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

### Security
- **Optional at-rest encryption of audit metadata:** when
  `audit_encryption_profile` is set to an Encryption Profile entity ID (from
  drupal/encrypt), the `metadata` column of every new audit row is encrypted at
  rest. Reads transparently decrypt via the `decodeMetadata()` accessor with
  graceful fallback to plain JSON for pre-encryption rows, so no data migration
  is required when enabling encryption on an existing install. The hash chain
  continues to hash plaintext canonical content (encryption only affects
  storage), so `drush mcp-sentinel:audit-verify` remains reliable. An encryption
  failure at runtime logs a warning and falls back to storing plaintext for that
  row (audit entries are never dropped). drupal/encrypt is now a required
  dependency.

### Fixed
- **Non-string entity labels no longer fatal the audit logger:** for config
  entities (and some content entities) `$entity->label()` returns a
  `TranslatableMarkup` object rather than a string. The audit logger passed it
  straight to `substr()`, which throws a `TypeError` under PHP 8.x — turning a
  legitimate governed save/delete into a fatal inside
  `hook_entity_presave()`/`hook_entity_delete()`. The label is now cast to a
  string before truncation.
- **Approval executor hardening (`mcp_sentinel_approval`):** replay and
  identity-safety guards on `McpApprovalExecutor`. `approve()`/`deny()` throw if
  the request is not pending (no double execute / duplicate audit row);
  `approve()` validates the stored target entity type via `hasDefinition()`
  before loading storage; a missing approver delete-access on a still-present
  target leaves the request **pending** (no longer mislabelled approved) while
  genuinely unexecutable cases (target gone, unknown type, UUID mismatch) are
  recorded approved with `executed=false` plus a truthful `reason`; and the
  queued target is bound by **UUID** as well as id so a reused id cannot delete
  the wrong entity.
- **Bulk tool fail-closed dispatch:** in `McpBulkOperationsTool`, a throwable
  from the destructive-op event dispatch is now treated as a veto (the id is
  reported as *queued*), so a dispatcher-level error can never let a gated
  delete proceed or be miscounted as failed.
- **DLP fail-open on PCRE runtime error:** `McpDlp::replaceMatches()` detects a
  NULL return from `preg_replace`/`preg_replace_callback` (e.g. on a
  backtrack-limit hit) and returns the **original value unchanged** instead of
  silently coercing NULL to `''`, logging a warning. Previously a PCRE error
  would blank the field value.
- **DLP partial mode fully masks short matches:** in partial masking mode a
  match whose length is ≤ 4 characters (equal to `PARTIAL_KEEP`) is now
  **fully replaced with `*`** instead of returned verbatim; longer matches keep
  last-4 semantics.
- **DLP `us_phone` regex matches no-separator format:** `(555)123-4567` (closing
  area-code paren with no following separator) is now matched (the separator
  after `)` is optional).

### Notes
- Pre-1.0 and in active development. Track planned work and report issues in the
  [drupal.org issue queue](https://www.drupal.org/project/issues/mcp_sentinel).

## [1.0.0-alpha1] - 2026-06-01

### Added
- Security presets and operation gates: master on/off switch plus independent
  read / write / delete / GraphQL-mutation toggles.
- `mcp_policy_profile` config entity for per-agent governance policy (operation
  gates, entity allow/deny lists, field redaction, role bindings, weight).
  Resolved by role with a `default` profile fallback; `update_10002` migrates
  existing flat settings. Full admin UI at
  `/admin/config/services/mcp-sentinel/profiles`.
- `McpPolicyResolver` service: `isGoverned(account)` and `resolve(account)` —
  OAuth-channel-primary governance detection and role-based profile resolution
  with deterministic highest-weight tie-break.
- `McpOauthContext` service (`mcp_sentinel.oauth_context`) — reads the
  server-validated OAuth agent channel (consumer `client_id` + token scopes)
  for the current request. Single seam between MCP Sentinel and simple_oauth.
- `agent_oauth_clients`, `agent_scopes`, `governed_role_fallback` settings in
  `mcp_sentinel.settings` (schema + install defaults). Controls the OAuth
  channel detection; role fallback defaults to `false`.
- Field-level redaction unified across JSON:API/REST (stripped) and GraphQL
  (`[REDACTED]`) via `hook_entity_field_access` and the `user.roles` +
  `oauth2_scopes` cache contexts.
- Audit logging of every MCP entity operation and GraphQL query/mutation, with
  configurable retention and automatic pruning.
- Content locks with TTL-based expiry to prevent agents from overwriting content
  a human is editing.
- HMAC-SHA256-signed, HTTPS-only webhooks fired on MCP-driven entity changes.
- `/drupal-mcp/context` (rich site-schema endpoint) and `/drupal-mcp/health`
  (status probe) controllers; the `mcp_api` role created on install.
- Governed Tool API plugins: site context, security policy, content lock, node
  create/update, media create, workflow transition, and bulk operations.
- `mcp_sentinel_server` submodule — registers the Tool plugins with `mcp_server`
  and wires per-tool OAuth scopes (`drush mcp-sentinel:setup` / `:teardown`).
- `mcp_sentinel_graphql` submodule — mutation/read gating, field redaction, and
  audit for the GraphQL Compose endpoint, plus a GraphQL SDL discovery tool.
- Base Drush commands: `mcp-sentinel:status`, `:audit-purge`, `:lock-clear`.
- `docs/CONNECTOR.md` — the connector ↔ Drupal contract: grant type, token
  endpoint, per-environment Consumer + scopes + TTL runbook, agent policy
  profile values, and end-to-end verification procedure.
- `phpcs.xml.dist`, `phpstan.neon.dist` (level 6), and unit/kernel/functional
  test coverage.

### Security
- MCP governance triggers on the **validated OAuth agent channel**
  (consumer/scope on the request's access token), not on role alone. An admin's
  direct cookie-session Drupal UI is never governed; only token-bearing agent
  traffic is governed and audited.
- Per-tool `mcp:read`/`mcp:write` scope enforcement via `mcp_server_oauth`
  third-party settings on each `mcp_tool_config`. Run
  `drush mcp-sentinel:setup --require-oauth` to apply.
- Governed redaction and entity-access decisions vary by both `user.roles` and
  `oauth2_scopes` cache contexts, preventing agent-channel responses from being
  served to cookie-session requests for the same user.
- Governance also triggers on the agent's **authenticated roles** as a
  configurable local-dev fallback (`governed_role_fallback`, default `false`),
  not the spoofable `X-MCP-Client` header. An agent cannot bypass policy by
  omitting the header; a non-agent user cannot be governed by adding it.
- The HMAC webhook signing secret is resolved from a **Key** entity
  (`webhook_secret_key`) instead of being stored as plaintext in exported
  configuration. `update_10001` migrates any existing plaintext secret into a
  Key. drupal/key is a required dependency.
- The `/drupal-mcp/context` endpoint does not disclose the Drupal version.

### Fixed
- `allow_read` is enforced on JSON:API/REST reads (the `view` operation was
  previously ungated outside GraphQL).
- `McpContentLock::isLocked()` no longer writes (deletes expired rows) on every
  read; expired locks are excluded by a query condition and reaped by cron.
- Uninstalling the module now removes the `mcp_api` role it creates on install.

[Unreleased]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-alpha1...1.0.x
[1.0.0-alpha1]: https://git.drupalcode.org/project/mcp_sentinel/-/tags/1.0.0-alpha1
