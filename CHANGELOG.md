# Changelog

All notable changes to MCP Sentinel are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-06-29

### Added
- **Per-entity-type destructive overrides on policy profiles (`entity_rules`).**
  A profile's global `allow_delete` / `allow_write` flags remain the default for
  every entity type, but an `entity_rules` map can now override them for one type
  at a time, e.g.

  ```yaml
  entity_rules:
    taxonomy_term:
      allow_delete: true
  ```

  The effective permission resolves as
  `entity_rules[type].allow_delete ?? allow_delete` (and the parallel
  `?? allow_write`). This lets an operator open delete for a single low-risk type
  (e.g. `taxonomy_term`, for taxonomy maintenance) while the global no-delete
  guarantee holds for node, media, paragraph, menu, redirect, file, and every
  other type. New entity methods `getEntityRules()`,
  `allowsDeleteForEntityType()`, and `allowsWriteForEntityType()` implement the
  override-then-fallback resolution, and `McpAccessChecker` consults them on the
  write and delete paths (the core-access hook and the bulk tool alike).
- The per-type delete overrides are editable in the profile UI at **Allowed
  operations → Per-entity-type delete overrides**, and the effective rule map is
  reported by `mcp_sentinel_security_policy` (surfaced to the connector as
  `entityRules` in `drupal_security_info`).

### Notes
- This is the *Sentinel* gate only — the Drupal role permission (e.g.
  `delete terms in <vocabulary>`) remains an independent second gate; a delete
  requires **both**.
- No Integration Contract change (contract v1.0-compatible); OAuth scopes,
  identity header, and server-authoritative authz are unchanged.
- No update hook: the new `entity_rules` field defaults to empty, so existing
  profiles are unchanged and behave exactly as before until a rule is added.
- Governance unchanged: server-authoritative authz, attribution, tamper-evident
  audit, DLP/redaction, the config-scope isolation, and the DEV-113 publish gate
  are untouched.

## [1.3.0] - 2026-06-29

### Changed
- **The publish gate is now value-aware on the JSON:API/REST write path.**
  Previously, a deny-publish profile forbade **every** edit to `moderation_state`
  (and `status`) via `hook_entity_field_access`, which also blocked the
  non-publish editorial transitions a content role grants — the agent could not
  set `draft`, `submit_for_review`, `restore`, or `archive` through the connector
  (it received `403 — Publishing is denied by MCP Sentinel`). The gate now inspects
  the **target value** and forbids only a transition to a *published* state
  (`moderation_state`) or a publish via the `status` flag (`status = TRUE`);
  non-publish transitions and unpublishing are allowed. The human-publish
  guarantee is unchanged — any published-state target is still denied with the
  same clear message, and a generic access probe (no pending value) defers to the
  value-bearing write-time check. (DEV-113)

### Added
- **`mcp_sentinel.moderation_gate`** service (`McpModerationGate`) — the single
  source of truth for "does this transition publish?" Both the field-access gate
  and `McpWorkflowTransitionTool` use it, so the JSON:API write path and the
  server-tool path agree on exactly which transitions are go-live. It is
  conservative: only a known, published target state counts as a publish.

### Notes
- No Integration Contract change — OAuth scopes (`mcp_read` / `mcp_write` /
  `mcp_config`), identity header, and server-authoritative authz are unchanged;
  this is contract v1.0-compatible.
- Governance unchanged: server-authoritative authz, attribution, tamper-evident
  audit, DLP/redaction, and the content-tier config-scope isolation are untouched.

## [1.2.0] - 2026-06-27

### Security
- Isolated the configuration tools behind a dedicated **`mcp_config`** OAuth scope.
  `mcp_sentinel_config_get`, `mcp_sentinel_config_list`, and `mcp_sentinel_config_set`
  now require `mcp_config` instead of `mcp_read` / `mcp_write`, so a content-tier token
  (holding only `mcp_read` / `mcp_write`) can no longer read or write Drupal configuration
  through MCP — config management is now isolated to the dev/config tier (the `developer`
  and `admin` tiers in `mcp-sentinel:agent-provision`, which already grant `mcp_config`).
  The transport-layer scope gate is in addition to the existing `allow_config_read` /
  `allow_config_write` / `denied_config_types` policy gates.

### Changed
- `mcp_config` is now part of the default `agent_scopes` so a token carrying only that
  scope is still recognized on the governed agent channel.

> **Upgrade action.** After updating, re-run `drush mcp-sentinel:setup --require-oauth`
> to re-tag the config tools with `mcp_config`. Ensure your config/dev consumer holds the
> `mcp_config` scope (the `oauth2_scope` entity must exist) and that content-tier consumers
> do **not**. Any consumer that previously called the config tools with only `mcp_write`
> will now be denied until granted `mcp_config`.

## [1.1.0] - 2026-06-26

### Security
- Hardened the default `denied_entity_types` to block secret-, governance-, and
  credential-bearing entity types — `oauth2_token`, `key`, `consumer`,
  `encryption_profile`, `mcp_tool_config`, `mcp_policy_profile` — in addition to `user`.
  Because a profile with an empty `allowed_entity_types` means "allow all (minus the
  denylist)", these were previously reachable by any profile with write access. New
  installs get the hardened default; `mcp_sentinel_update_10012()` additively merges the
  list into existing profiles (idempotent; operator-added denies are preserved).

### Fixed
- **CI (phpunit)**: `GraphqlFieldResultsAlterTest` saved `mcp_sentinel.settings` without
  installing the `mcp_sentinel_audit_log` schema, so the `ConfigEvents::SAVE` audit subscriber
  errored on a missing table (2 errors on the drupal.org pipeline, red since 1.0.0-beta5).
  `setUp()` now installs the audit-log schema, matching the sibling kernel tests. Test-only —
  no runtime change.

## [1.0.0] - 2026-06-26

First **stable** release. Promotes the `1.0.0-alpha1` … `1.0.0-beta6` pre-release
series to a stable 1.0.x line under semantic versioning. There are **no code changes
since `1.0.0-beta6`** — this tag marks API stability for the governance surface
(policy-profile fields, MCP tools, events, and Drush commands). Supported core:
`^10.3 || ^11`. Headline scope of the 1.0.0 line, consolidated from the pre-release
entries below:

### Added
- **Two-persona, environment-keyed configuration governance**: per-tier
  `McpPolicyProfile` capabilities (`allow_config_read`, `allow_config_write`,
  `denied_config_types`), governed config MCP tools (`mcp_sentinel_config_get` /
  `_list` / `_set`), and a `ConfigEvents::SAVE` hard-deny + audit subscriber.
- **Publish gate**: agent-authored content lands unpublished (`deny_publish`,
  `max_moderation_state`), with a `status = 0` fallback for unmoderated types.
- **Approval workflow + break-glass**: `mcp_sentinel_approval` gates `delete`,
  `config_import`, and `module_disable`; time-boxed, approval-gated `mcp_admin`
  elevation (never standing).
- **Tamper-evident audit**: HMAC-SHA256 audit hash chain, at-rest audit-metadata
  encryption (`real_aes` encryption profile), DLP redaction, anomaly detection, SIEM
  streaming, and reliable governance webhooks.
- **Admin UX**: dashboard + settings menu links and an in-form setup guide.

See the `1.0.0-beta*` / `1.0.0-alpha*` sections below for full per-release detail.

## [1.0.0-beta6] - 2026-06-26

### Fixed
- **PHP 8.4 compatibility**: the audit-log CSV export (`McpAuditController::buildCsvResponse()`)
  called `fputcsv()` without the `$escape` argument, which PHP 8.4 deprecates — under the
  test deprecation handler this errored, and on PHP 8.4 sites the export would emit a
  deprecation notice. The separator/enclosure/escape are now passed explicitly (no change to
  output). Fixes the red `McpAuditFilterExportTest` CSV jobs in CI.
- **Test**: `McpDashboardTest::testDashboardRendersForPermittedUser` granted the test user
  `access site reports` so the core Reports index (`/admin/reports`) renders; previously the
  page 403'd and the dashboard menu-link assertion failed. Added an explicit 200 assertion so
  the cause is obvious if it regresses.

## [1.0.0-beta5] - 2026-06-26

### Added
- **Configuration governance (two-persona, environment-keyed least privilege).**
  A new layer that governs configuration operations and content publishing under
  the resolved policy profile, additive and default-off:
  - **Profile fields** (`McpPolicyProfile`): `allow_config_read`,
    `allow_config_write`, `denied_config_types` (name-prefix denylist),
    `deny_publish`, and `max_moderation_state`. All default to the safe value
    (config off, publishing denied); existing profiles are backfilled by
    `mcp_sentinel_update_10011()`. A new "Configuration governance" tab on the
    policy-profile form edits them.
  - **Config access seam**: `McpAccessChecker::checkConfigAccess()` mirrors the
    entity-access pattern (master switch, IP allowlist, denylist, read/write
    gates). Three new governed MCP tools — `mcp_sentinel_config_get`,
    `mcp_sentinel_config_list`, `mcp_sentinel_config_set` — registered via
    `drush mcp-sentinel:setup`. Config reads/lists honor `audit_log_reads`.
  - **Hard-deny config subscriber**: a `ConfigEvents::SAVE` subscriber audits
    every governed config save (`config_save`, with a redaction/DLP-aware diff
    via `McpAuditLogger::computeConfigDiff()`) and hard-denies — reverting the
    persisted value and throwing — a governed write to a `denied_config_types`
    name, closing the direct-`Config::save()` bypass.
- **Publish gate.** Agent-authored content lands unpublished unless a profile
  opts in. Enforced at the `mcp_sentinel_workflow_transition` tool (value-aware:
  blocks transitions to a published state and beyond `max_moderation_state`),
  with `hook_entity_field_access` (`edit` on `moderation_state`/`status`) and an
  `entity_presave` `setUnpublished()` fallback as defense in depth.
- **Approval coverage for config/admin ops.** `gated_operations` now defaults to
  `delete`, `config_import`, `module_disable`. A non-entity
  `McpDestructiveActionEvent` + subscriber queue these for human approval, and
  `McpApprovalExecutor` replays `config_import` and `module_disable` on approval.
- **`mcp-sentinel:agent-provision <tier> --env`** drush command — idempotently
  provisions a tier's role, dedicated agent account, and OAuth consumer (one
  source of truth so connector/Keychain/consumer cannot drift). Secrets remain a
  human action.
- **Time-boxed `mcp_admin` break-glass.** The admin role is never standing:
  `mcp-sentinel:break-glass <uid>` raises an always-gated approval request; on
  approval the role is granted with a TTL (`break_glass_ttl_seconds`) and
  recorded as an `mcp_admin_grant` entity, then auto-revoked by
  `mcp_sentinel_approval_cron()`.
- **`config_governance` status guard.** `McpUrgentConditions` emits a critical
  condition (surfaced on the dashboard and as a non-zero `mcp-sentinel:status`
  exit) when config write is reachable but governance is not live — never fail
  open.

## [1.0.0-beta4] - 2026-06-22

### Fixed
- Drupal.org GitLab CI was red on `1.0.x` (phpcs, phpstan, phpunit). All fixes
  are in code introduced by the fail-loud requirement plus one type-hint:
  - **phpunit** — `McpRequirementsTest` invoked `mcp_sentinel_requirements()`
    directly, which uses the `REQUIREMENT_*` severity constants from
    `core/includes/install.inc`; that file is loaded by core before runtime
    requirements run but not in a kernel test, causing "Undefined constant
    REQUIREMENT_WARNING". The test now loads `install.inc` in `setUp()`. It also
    installs the `path_alias` entity schema, because the warning the hook builds
    renders a settings link via `Url::fromRoute()`, which resolves path aliases
    (a latent failure the undefined-constant error had been masking).
  - **phpstan** — `McpSentinelServerCommands::setup()` type-hinted the
    `mcp_tool_config` entity with the optional `mcp_server_tool_bridge` module's
    concrete class, which static analysis cannot resolve (6 errors). Retyped to
    `\Drupal\Core\Config\Entity\ConfigEntityInterface`.
  - **phpcs** — fixed three 81-char lines in `mcp_sentinel.install` and a
    non-capitalized doc-comment short description in `McpRequirementsTest`.

### Added
- Admin menu links for the governance **dashboard** (`/admin/reports/mcp-sentinel`,
  under Reports) and the **settings** form (`/admin/config/services/mcp-sentinel`,
  under Configuration → Web services). Both were previously reachable only by direct
  URL or local-task tabs, so the dashboard never appeared in the Reports listing and
  the settings form never appeared in the Web services group. Access is unchanged —
  each link inherits its route's existing permission requirement
  (`mcp_sentinel.links.menu.yml`).
- A collapsed, unobtrusive **"Setup & configuration guide"** on the settings form
  (`McpSettingsForm`): a short site-builder quickstart (install → register tools →
  make requests governable → define a policy profile → configure a signing Key),
  linking to policy profiles, the Keys UI, and the shipped `README.md` / `INSTALL.md`
  / `API.md`. It is a curated quickstart, not a copy — the README and `hook_help()`
  remain the source of truth.
- CI: Slack release notification (`.github/workflows/release-notify.yml`) — posts to the
  maintainers' release channel on release tags; no-ops without the `SLACK_WEBHOOK_RELEASES` secret.
- Fail-loud runtime requirement (`mcp_sentinel_requirements('runtime')`): the
  status report now raises a WARNING ("MCP Sentinel: not governing any request")
  when the module is enabled but governance can never engage — i.e. both
  `agent_scopes` and `agent_oauth_clients` are empty and the local-dev role
  fallback is not usable (so `McpOauthContext::isAgentChannel()` can never fire),
  or no `mcp_policy_profile` exists (so `McpPolicyResolver::resolve()` always
  returns NULL). The check mirrors the real governance decision and links to the
  settings form. This closes the silent no-op footgun where the module fails open
  without telling the operator.
- CI: Dependabot patch/minor PRs now auto-merge once checks pass (majors still
  reviewed), via the org reusable workflow
  (`.github/workflows/dependabot-automerge.yml` calls the shared
  `dependabot-automerge.yml` in `Wilkes-Liberty/.github`).
- Adopted the shared **Integration Contract v1.0** (published by the companion
  connector at `docs/integration-contract.md`). The connector's `X-MCP-Client`
  label is now recorded in the audit log — log-only, as the `mcp_client`
  metadata field, never an enforcement signal. `docs/CONNECTOR.md` documents the
  contract surface (log-only client identity, `mcp_read`/`mcp_write` scopes, the
  `/drupal-mcp/context` endpoint, and server-authoritative authorization keyed on
  role + scopes). Compatibility: mcp_sentinel ≥ 1.0 ↔ drupal-mcp-connector ≥ 0.6.
- Adopted the organization governance baseline for GitHub. Added a CHANGELOG
  check (`.github/workflows/changelog.yml`, with a `no-changelog` bypass label)
  and CHANGELOG autoupdate (`.github/workflows/changelog-autoupdate.yml`), both
  calling the shared reusable workflows in `Wilkes-Liberty/.github`. Added
  Dependabot (`.github/dependabot.yml`) for the `composer` and `github-actions`
  ecosystems on a weekly schedule. Added a non-blocking PHP dependency audit
  (`.github/workflows/composer-audit.yml`) that runs `composer audit` on pull
  requests and on pushes to `1.0.x`; CodeQL is intentionally omitted as it does
  not support PHP.

### Changed
- CI: the CHANGELOG check now exempts Dependabot PRs automatically (author
  `dependabot[bot]`), so dependency bumps no longer need a changelog entry or the
  `no-changelog` label.
- **OAuth scope machine ids standardized to underscores: `mcp:read` →
  `mcp_read`, `mcp:write` → `mcp_write`.** This is a **contract change**.
  Governance matches the scope *name* carried on a validated token against
  `mcp_sentinel.settings:agent_scopes`; the install default, the settings-form
  default, the `mcp-sentinel:setup` tool→scope tags, and all docs now use the
  underscore form so token, tagging, and governance agree end-to-end. **Action
  required for existing installs that created colon-form scopes:** rename your
  `Oauth2Scope` entities (and any consumer `scopes`) and update
  `agent_scopes` to the underscore form. See `docs/UPGRADE.md`.
- Renamed all references to the companion connector to its final public name
  **`drupal-mcp-connector`** (formerly published under its working name; repo
  `Wilkes-Liberty/drupal-mcp-connector`, npm `drupal-mcp-connector`). The
  `X-MCP-Client` label default is now `drupal-mcp-connector/<version>`.
- CI: made the GitHub-mirror workflows self-contained instead of calling reusable
  workflows in the private `Wilkes-Liberty/.github` repo. A public repository
  cannot use reusable workflows from a private one, so every PR run was failing at
  startup ("workflow file issue"). `changelog.yml` and `dependabot-automerge.yml`
  now inline their logic (no external repo dependency, so forks work too);
  `changelog-autoupdate.yml` is removed (it required an org GitHub App). Also
  dropped the `composer` Dependabot ecosystem — the Drupal contrib deps live on
  packages.drupal.org, not Packagist, so Dependabot could not resolve them.
- Docs clarity: INSTALL.md now states the underscore scope form is the default
  (most sites need no change) and links the colon-form migration section directly;
  added an "agent discovery" pointer to the `/drupal-mcp/context` endpoint after
  OAuth setup. docs/CONNECTOR.md clarifies that `mcp_server_oauth` is optional
  (per-tool transport-layer scope enforcement) and is not required for governance.

## [1.0.0-beta3] - 2026-06-02

### Fixed
- Drupal.org CI code-quality jobs: added project words for CSpell, fixed the
  Stylelint CSS property order, removed a redundant ESLint `'use strict'`, and
  wrapped a PHPCS line-length warning. No functional change.

### Changed
- Module, composer, and project-page descriptions updated to the current
  governance feature set.

## [1.0.0-beta2] - 2026-06-02

### Added
- Reusable in-form multi-row list editor trait.
- Live policy-preview summary on the profile form; refreshes via AJAX when gate or cap fields change.
- McpMetrics dashboard-data service (`mcp_sentinel.metrics`): read-only, window-bounded aggregation over the existing audit, webhook, approval, anomaly, and config stores.
- McpUrgentConditions service (`mcp_sentinel.urgent_conditions`): evaluates critical/warning conditions (broken hash chain, unresolvable encryption profile, governance off with recent traffic, unresolvable webhook signing key) plus the operator broadcast.
- McpChartRenderer service (`mcp_sentinel.chart_renderer`): renders metric series as charts with a self-contained inline-SVG fallback and an optional `drupal/charts` upgrade (added to composer `suggest`).
- Governance dashboard at `/admin/reports/mcp-sentinel` (`McpDashboardController`): urgent-conditions banner, posture hero, status tiles, chain-integrity card, top-agents and denied-by-policy panels, quick actions, and an active-controls strip — each widget guarded so a failing metric degrades gracefully. Local-task tabs (Dashboard · Audit log · Webhook deliveries · Approvals) navigate the report surface.
- Six dashboard charts (audit volume with anomaly markers, allowed-vs-denied, operation mix, top agents, denied reasons, webhook health) via `McpChartRenderer`, with a server-rendered time-window toggle (`?window=24h|7d|30d`, default 24h) and click-to-drill links into the filtered audit / webhook logs.
- CSRF-protected **Verify chain now** dashboard action (`mcp_sentinel.verify_chain`): re-runs `verifyChain()` and writes `@state` `mcp_sentinel.last_verify` in the same shape as the Drush command, then redirects to the dashboard with a status message.
- Site-wide **critical** urgent banner via `hook_page_top()`: shown on admin pages (only to users with *View MCP Sentinel audit log*) so a broken hash chain or unresolvable signing key is seen even off the dashboard, with per-user dismissal (private tempstore) via a CSRF-protected endpoint. Warning/info conditions remain dashboard-only.

### Changed
- Audit log listing moved from `/admin/reports/mcp-sentinel` to `/admin/reports/mcp-sentinel/audit` (the base path is now the governance dashboard); the route name `mcp_sentinel.audit_log` and the export route are unchanged.
- Settings form reorganized into vertical tabs; added a dashboard operator-broadcast message.
- DLP patterns edited via an add/remove row table (config storage unchanged).
- Anomaly rules edited via an add/remove row table (config storage unchanged).
- Webhook endpoints edited via a dynamic add/remove editor (config storage unchanged).
- Policy-profile form grouped into vertical tabs (Identity · Allowed operations · Entity scope · Redaction · Rate limits &amp; quotas · Network/IP).
- Audit log listing: colored status/operation badges, per-row expandable metadata (`<details>`), prominent CSV/JSON export buttons, and a mini volume/allowed-vs-denied chart strip at the top (reusing `McpChartRenderer` + `McpMetrics`).
- Webhook delivery log: colored status badges (sent/failed/pending/failed_ssrf), per-row expandable payload/response (`<details>`), a status + endpoint filter form (`McpWebhookFilterForm`), and a CSRF-protected prune action.
- Approval queue: age and reason columns, a status filter, and a conditional "Approvals" dashboard tab (shown when `mcp_sentinel_approval` is enabled).

## [1.0.0-beta1] - 2026-06-02

> Hardening, test-coverage, and documentation work over `1.0.0-alpha2`
> (Phase 5). Additive only — no breaking changes. Notably closed a JSON:API
> entity-create governance bypass and three holistic-security-review findings.

### Security
- **Webhook SSRF guard now covers IPv6-only (AAAA) hosts (F17).**
  `McpWebhookWorker::validateAndResolveHost()` resolved only IPv4 A records, so a
  hostname with ONLY an AAAA record (e.g. resolving to `::1` or `fd00::/8`)
  slipped through unpinned and let cURL connect to a private IPv6 at send time.
  The worker now also resolves AAAA records, runs every resolved IP (v4 and v6)
  through the internal-range guard, blocks fail-closed if ANY resolved address is
  internal, and pins a public IPv6 via `CURLOPT_RESOLVE` using the bracketed
  `host:port:[ipv6]` format. HTTPS enforcement is unchanged.
- **IP allowlist now enforced at the write tools' `checkAccess()` (F15).** The
  three read tools gated the IP allowlist in `checkAccess()`, but the four write
  tools (`McpNodeOperationsTool`, `McpBulkOperationsTool`, `McpMediaUploadTool`,
  `McpWorkflowTransitionTool`) only checked the permission, so an IP-blocked
  governed agent could probe tool availability and the early-return error paths
  skipped the per-entity IP gate. Each write tool's `checkAccess()` now resolves
  the profile and, when governed and `isClientIpAllowed()` fails, returns
  `AccessResult::forbidden()` with `max-age 0`. Ungoverned accounts are unaffected.
- **JSON:API filter-access denials now carry cache contexts (cache-bleed fix,
  F16).** `McpAccessChecker::getJsonApiFilterAccess()` returned forbidden results
  without the `user.roles` + `oauth2_scopes` cache contexts every other governed
  result attaches, so the filter-access cache could serve a governed deny to a
  non-governed account (or vice-versa). Forbidden results now add those contexts
  plus the settings/profile cache tags, and are `max-age 0` when the profile has a
  non-empty `allowed_ips` list.
- **JSON:API entity creation is now governed (closed a write-plane bypass).**
  `hook_entity_access` does not fire for entity CREATE, so JSON:API `POST` (new
  entity) — routed through `_entity_create_access` → `hook_entity_create_access` —
  previously bypassed the write gate, the allowed/denied entity-type policy, and
  the IP allowlist. The module now implements `mcp_sentinel_entity_create_access`,
  delegating to a shared `McpAccessChecker::checkCreateAccess()` that enforces the
  master switch, IP allowlist, entity-type allow/deny policy, and write gate with
  the same cacheability rules. Create-access governance now matches existing-entity
  (PATCH/DELETE) semantics.
- **JSON:API IP allowlist now covers collections, not just individual resources.**
  The IP gate fired via `hook_entity_access` (individual `/{uuid}` reads) but the
  collection endpoint is governed by `hook_jsonapi_entity_filter_access`, which
  only checked entity-type allow/deny — so a governed agent from a disallowed IP
  could still enumerate collections. The IP allowlist is now enforced for ALL
  governed JSON:API traffic (collection, individual, and writes) at the
  `McpJsonApiPageLimitSubscriber` (`KernelEvents::REQUEST`) seam, which denies
  (403) when `isClientIpAllowed()` fails. Empty `allowed_ips` imposes no
  restriction; the individual-entity path remains gated by `hook_entity_access`
  (defence in depth).

### Added (tests)
- **GraphQL governance** (`mcp_sentinel_graphql`): redaction, DLP masking, and
  result-cap coverage for the field-results-alter hook, plus mutation/query
  gating and blocked-operation auditing.
- **Content tools**: behavioral kernel coverage for the node-operations,
  media-upload, and workflow-transition tools, and the content-lock, security-
  policy, and site-context tools.
- **OAuth agent-channel end-to-end** (`McpOauthChannelTest`): the role-fallback
  governed path enforces write gates over real HTTP, non-governed users are
  unaffected, successful governed writes are audited, and the OAuth-primary model
  ignores the `mcp_api` role when the fallback is disabled.
- **JSON:API write governance** (`McpJsonApiWriteGovernanceTest`,
  `McpContentToolGovernanceTest`): governed `POST`/`PATCH` blocked when
  `allow_write=FALSE` (403) and allowed when on, read-gate enforcement,
  denied-type and disallowed-IP blocks, the `page[limit]` cap via the live
  subscriber (400), and a non-governed admin bypassing Sentinel gates.
- **Phase 4 controls, functional** (`McpPhase4ControlsFunctionalTest`):
  rate-limit blocks after threshold; exfiltration page-cap returns 400 over real
  HTTP; IP allowlist denies an out-of-CIDR client (and permits when unrestricted);
  the anomaly detector fires on seeded audit rows and the dispatcher runs cleanly.
- **Governed-request harness trait** (`McpGovernedRequestTrait`): HTTP Basic auth
  and query-string support for the functional suite.
- **Server submodule registration** (`McpServerRegistrationTest`): every base
  Tool plugin is discoverable by `plugin.manager.tool`, instantiates without
  error, is covered by the `McpSentinelServerCommands::TOOLS` constant, and uses
  an `mcp:*` scope.
- **Drush commands** (`McpDrushCommandsTest`): all six base commands exercised
  directly — `audit-verify` (clean → success, tampered → failure), `webhook-prune`,
  `lock-clear`, `audit-purge`, `webhook-replay`, and `status`.
- **Update-hook chain 10001–10010** (`McpUpdateHookChainTest`): each hook
  individually (idempotency, schema and config end-state) plus a full-chain
  integration test that confirms the audit hash chain stays intact across the
  whole update path.
- **Uninstall cleanliness** (`McpUninstallTest`): the `mcp_sentinel_*` tables,
  module config (settings + all profiles), and `mcp_api` role are all removed,
  leaving no orphaned footprint.
- **Field-access redaction** (`McpFieldAccessRedactionTest`): governed agent on a
  redacted field is forbidden, non-governed users are neutral, non-view
  operations are not redacted, and results always carry the `user.roles` +
  `oauth2_scopes` cache contexts.
- **Create-access + cache invariants** (`McpAccessCheckerTest`,
  `McpIpAllowlistTest`): `checkCreateAccess()` write-gate, denied-type, allowlist,
  and master-switch cases, and `max-age 0` on all forbidden branches when
  `allowed_ips` is non-empty.

### Documentation
- Added `mcp_sentinel_help()` (`hook_help`) — a routed overview page at
  `/admin/help/mcp_sentinel` covering the trust model, capabilities, submodules,
  and links to the settings and audit routes.
- Added `INSTALL.md` (install steps, dependencies, submodule enablement, the
  OAuth/connector pointers, and the reverse-proxy requirement for IP allowlisting)
  and `API.md` (the `McpDestructiveOpEvent` veto seam, the `McpEntityEvent`
  audit/webhook seam, the Tool plugin contract, the policy-profile entity, and
  the public services).
- README: added a consolidated admin-routes and Drush-command reference, pointers
  to `INSTALL.md`/`API.md`, and a note explaining why `composer.json` keeps
  `minimum-stability: dev` (the dev-only `drupal/mcp_server` has no stable tag).
- Clarified the external tool-count claims: the README "66 tools" now
  unambiguously refers to the external `drupal-mcp-connector` Node connector (66
  connector tools across 9 modules), not Sentinel's own plugins; the
  `composer.json` suggest for `drupal/mcp_tools` cites that project's own count
  (222 tools across 34 submodules).

## [1.0.0-alpha2] - 2026-06-02

### Added
- **Per-profile IP allowlisting:**
  - A new `allowed_ips` field on every `mcp_policy_profile` config entity accepts
    a sequence of IPv4/IPv6 addresses and CIDR blocks. An empty list means no
    restriction (any IP permitted); this is the safe default and the value set by
    `update_10010` on all existing profiles.
  - `McpAccessChecker::checkEntityAccess()` now enforces the allowlist as an
    early-return check before operation gates. The client IP is obtained via
    Symfony's trusted-proxy-aware `Request::getClientIp()` — never from raw
    `X-Forwarded-For`/`X-Real-IP` headers — so an attacker who forges an allowed
    IP in a header cannot bypass the allowlist unless the connecting proxy is
    already in Drupal's `reverse_proxy_addresses` list.
  - IPv4/IPv6 single-address and CIDR matching is done by
    `Symfony\Component\HttpFoundation\IpUtils::checkIp()`, which is bundled with
    Drupal and handles both address families and prefix notation correctly.
  - The policy profile add/edit form gains an *IP allowlist* fieldset with a
    validated textarea (one IP or CIDR per line). Each line is validated on save
    with `filter_var()` plus CIDR prefix-length range checks; malformed entries
    are rejected. The field description documents the reverse-proxy requirement.
  - **Trusted-proxy requirement (IMPORTANT):** IP allowlisting requires Drupal's
    reverse-proxy settings to be correctly configured in `settings.php`
    (`$settings['reverse_proxy'] = TRUE` and `$settings['reverse_proxy_addresses']`).
    Without those settings, `getClientIp()` returns the proxy's IP rather than the
    real client's. The README documents this prominently. An empty `allowed_ips`
    list (the default) disables IP enforcement and is always safe to leave in place
    if trusted proxies are not configured.
  - Scope: enforcement covers the entity-access layer (`McpAccessChecker`,
    `hook_entity_access`) as well as `McpContentLockTool`, `McpSecurityPolicyTool`,
    `McpSiteContextTool`, and the `/drupal-mcp/context` endpoint. All governed
    paths enforce the same IP gate via a shared
    `McpAccessChecker::isClientIpAllowed()` helper — a single canonical
    implementation.
  - **Cache safety:** when a profile has a non-empty `allowed_ips` list, EVERY
    `AccessResult` returned by `checkEntityAccess()` is marked `max-age 0`
    (uncacheable). Client IP is not a Drupal cache context; a cached "allowed"
    result could be re-served to a later request from the same account but a
    different, disallowed IP. The `/drupal-mcp/context` response carries
    `Cache-Control: no-store` for the same reason.
  - The IP gate is applied strictly to governed requests (accounts for which a
    policy profile resolves). Ungoverned cookie-session traffic is never affected.
  - `update_10010` backfills `allowed_ips: []` on all existing profiles during a
    `drush updb` run.
- **Anomaly detection & alerting:** cron-evaluated rules over the MCP audit log
  stream. The new `McpAnomalyDetector` service (`mcp_sentinel.anomaly_detector`)
  evaluates all enabled anomaly rules on each cron run. Each rule specifies an
  `operation_pattern`, a `window_seconds` lookback, and a `count threshold`. When
  the count of matching rows within the window meets or exceeds the threshold,
  the rule fires. Patterns use an exact `=` match by default, so a pattern like
  `entity` does not silently match both `entity_save` and `entity_delete`; append
  `*` to opt in to prefix matching (`entity*` matches everything starting with
  `entity`). Alerts are dispatched through up to three channels via the new
  `McpAlertDispatcher` service (`mcp_sentinel.anomaly_alert_dispatcher`): the
  `mcp_sentinel` logger channel (warning-level; on by default), email (configured
  via `anomaly_alert_email`; disabled when empty), and webhook (enqueues an
  `mcp.anomaly.alert` event through the `McpWebhookQueueManager`, inheriting
  retry/SSRF/HMAC — enabled via `anomaly_alert_webhook`). Alert storms are
  prevented by mandatory debounce: a rule fires at most once per
  `debounce_seconds` (default 3600), stored in `@state` under
  `mcp_sentinel.anomaly_last_alert.{rule_id}`. Zero enabled rules ship by
  default — operators opt in per-site to avoid false positives during content
  imports. `update_10009` seeds the anomaly settings on existing installs. The
  settings form gains an *Anomaly detection* fieldset for enabling detection,
  configuring alert channels, and managing rules via a pipe-delimited textarea.
  - **Governed denied_access auditing:** to give the detector a reliable signal,
    all governed Tool plugins (`McpBulkOperationsTool`, `McpNodeOperationsTool`,
    `McpWorkflowTransitionTool`, `McpMediaUploadTool`) now write a `denied_access`
    audit row whenever a governed agent is denied by policy (`McpAccessChecker`)
    or core entity access. In `McpBulkOperationsTool`, one row is written per
    denied entity ID, so an agent hammering N forbidden deletes produces N rows —
    the correct input for a `denied_access_storm` count-threshold rule. The
    `audit_log_reads` toggle is intentionally ignored; `denied_access` is a
    security event logged whenever `audit_enabled` is true. Each row carries
    `tool`, `entity_type`, `id`, `operation`, and `reason` in its metadata. Scope
    is the explicit Tool execution path; JSON:API/GraphQL denial-logging is a
    future enhancement.
- **Reliable webhooks — queued delivery with retry/backoff, multiple endpoints,
  per-event filtering, delivery log + replay, and an SSRF guard:** webhook
  delivery moved off the old fire-and-forget `httpClient->requestAsync()` path
  (which silently lost notifications if PHP exited before the promise settled)
  onto the Drupal queue system. `McpEventDispatcher::dispatch()` keeps its public
  signature, but now enqueues via the new `McpWebhookQueueManager`
  (`mcp_sentinel.webhook_queue_manager`): for each enabled endpoint whose event
  filter matches, it writes a `pending` row to the new
  `mcp_sentinel_webhook_delivery` table and pushes an item onto the
  `mcp_sentinel_webhook_delivery` queue.
  - **Multiple endpoints + per-event filtering:** the new `webhook_endpoints`
    setting is a sequence of `{id, label, url, secret_key, events[], enabled}`
    maps. An endpoint receives only events whose name is in its `events` list
    (empty = all events). HTTPS is required.
  - **Retry + exponential backoff:** the `McpWebhookWorker` QueueWorker
    (`id: mcp_sentinel_webhook_delivery`, cron time 30 s) POSTs the signed body
    and, on a non-2xx response or network error, schedules a retry — 5 attempts
    with backoff intervals of 30 s, 5 min, 30 min, 2 h, 8 h. The delivery row's
    `next_attempt` gates early sends (not-yet-due rows are requeued unchanged);
    after the 5th attempt the row is marked `failed`. A row already `sent` (or
    terminally `failed`/`failed_ssrf`) short-circuits with no HTTP call, so a
    duplicate queue item or concurrent worker can never double-send.
  - **SSRF guard (two layers):** Layer 1 at enqueue time rejects non-HTTPS URLs
    and obvious internal literals (`localhost`, `127.*`, `0.0.0.0`, `::1`).
    Layer 2 runs in the worker at send time (DNS can rebind after enqueue):
    literal IPs are validated directly and hostnames are resolved via
    `gethostbynamel()`, blocking any address in a private/loopback/link-local/
    reserved range (RFC1918 `10/8`, `172.16/12`, `192.168/16`, link-local
    `169.254/16`, loopback `127/8` + `::1`, unique-local `fc00::/7`, etc.);
    blocked rows are marked `failed_ssrf`. A global `allow_internal_webhook_urls`
    flag (default `FALSE`) disables Layer 2 only for legitimate internal-network
    deployments; HTTPS enforcement always applies.
  - **HMAC signing:** the body is signed with HMAC-SHA256 using the endpoint's
    Key-resolved secret and sent in the `X-MCP-Signature: sha256=…` header.
  - **Delivery log UI + replay:** a report at
    `/admin/reports/mcp-sentinel/webhooks` (permission `administer mcp sentinel`)
    lists recent deliveries with status, attempts, last response code and next
    attempt. A CSRF-protected **Replay** action (and `drush
    mcp-sentinel:webhook-replay <id>`) resets a `failed`/`sent` row to `pending`,
    attempts `0`, and re-queues it.
  - **Retention/prune:** the `webhook_delivery_retention_days` setting (default
    30) bounds table growth; `drush mcp-sentinel:webhook-prune` and `hook_cron`
    delete rows older than the window.
  - **Migration:** `update_10007` creates the delivery-log table; `update_10008`
    seeds the retention/opt-out defaults and migrates a legacy single
    `webhook_url`/`webhook_secret_key`/`webhook_enabled` into one
    `webhook_endpoints` entry (legacy keys retained for review). The settings
    form gains a *Reliable webhooks* section managing endpoints, retention and
    the internal-URL opt-out, and keeps the legacy single-endpoint fields visible
    with a deprecation notice.
- **Per-profile exfiltration guards (result-count, response-size, JSON:API page
  ceiling):** each `mcp_policy_profile` now carries `result_count_cap` (default
  `0` = unlimited) and `response_size_cap` (default `0` = unlimited) fields. A
  cap of `0` short-circuits the guard; no overhead on unlimited profiles. The
  new `McpExfiltrationGuard` service (`mcp_sentinel.exfiltration_guard`) enforces
  both caps at three seams:
  - **Tool output** — `McpBulkOperationsTool` truncates the `succeeded` result
    list to `result_count_cap` before returning `ExecutableResult::success()`.
    When truncation occurs, `_result_truncated: true` and `_result_cap: <n>` are
    added to the result data so the agent is never silently misled. The
    `response_size_cap` is also enforced at this seam: because all write
    operations have already executed, the payload is **truncated** (not
    rejected) to fit under the cap — returning failure after a completed write
    batch would misreport success as failure and could trigger agent retries that
    toggle publish/unpublish state. When size truncation occurs, `_size_truncated:
    true` and `_size_cap: <n>` are added; the success message notes the
    truncation. Pure-read tools may still use `checkResponseSizeCap()` which
    returns `ExecutableResult::failure()` before any data is materialised.
  - **JSON:API page ceiling** — a `KernelEvents::REQUEST` subscriber
    (`McpJsonApiPageLimitSubscriber`, priority -20) intercepts `page[limit]`
    parameters for governed agents, throwing HTTP 400 before the query runs.
    Path matching uses `str_contains('/jsonapi/')` rather than
    `str_starts_with('/jsonapi/')` so that URL-language-negotiated paths such as
    `/en/jsonapi/node/article` are correctly governed. Non-positive `page[limit]`
    values (0, negative, non-numeric) are passed through without a cap comparison
    and left for JSON:API's own parameter validation. Note:
    `hook_jsonapi_resource_params_alter` does NOT exist in Drupal 11.3 core;
    this subscriber is the correct implementation path.
  - **GraphQL multi-value field lists** — `hook_graphql_compose_field_results_alter`
    in `mcp_sentinel_graphql.module` truncates field result lists to
    `result_count_cap` as a third pass after field-name redaction and DLP
    masking. Non-governed requests are unaffected.
  The profile add/edit form gains an *Exfiltration guards* fieldset exposing both
  cap fields. Recommended starting values: 500 result items / 2 097 152 bytes
  (2 MB). `update_10006` backfills both fields on existing
  profiles to `0` (unlimited). Ungoverned requests are never capped.
- **Per-profile rate limiting & quotas via core flood:** each `mcp_policy_profile`
  now carries `rate_limit_requests` (default `0` = unlimited) and
  `rate_limit_window` (default `60` seconds) fields. When `rate_limit_requests`
  is non-zero, the `McpRateLimiter` service (`mcp_sentinel.rate_limiter`)
  enforces the limit using Drupal's core `@flood` service. The flood key is
  `mcp_sentinel.profile.{profile_id}.{uid}` — keyed on the server-resolved
  authenticated UID only, preventing key-cycling bypass attacks. A `0` request
  limit short-circuits before touching flood. Enforcement fires at the top of
  all four governed Tool plugins: `mcp_sentinel_node_operations`,
  `mcp_sentinel_bulk_operations`, `mcp_sentinel_media_create`, and
  `mcp_sentinel_workflow_transition`. Over-limit calls log an audit row with
  operation `rate_limit_exceeded` and return a failure result equivalent to
  HTTP 429. The profile add/edit form gains a *Rate limits* fieldset with the
  two new fields. `update_10006` backfills the fields on existing profiles:
  `rate_limit_window` defaults to `60` (so that setting
  `rate_limit_requests > 0` on an upgraded profile takes effect immediately);
  `rate_limit_requests`, `result_count_cap`, and `response_size_cap` default
  to `0` (unlimited). Recommended prod starting point: 300 requests / 60 s
  window.
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

[Unreleased]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta4...1.0.x
[1.0.0-beta4]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta3...1.0.0-beta4
[1.0.0-beta3]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta2...1.0.0-beta3
[1.0.0-beta2]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-beta1...1.0.0-beta2
[1.0.0-beta1]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-alpha2...1.0.0-beta1
[1.0.0-alpha2]: https://git.drupalcode.org/project/mcp_sentinel/-/compare/1.0.0-alpha1...1.0.0-alpha2
[1.0.0-alpha1]: https://git.drupalcode.org/project/mcp_sentinel/-/tags/1.0.0-alpha1
