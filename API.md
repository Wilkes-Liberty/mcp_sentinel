# MCP Sentinel API & extension points

This document describes the public seams a site builder or integrator uses to
extend MCP Sentinel: the events you can subscribe to, the Tool plugin contract,
the policy-profile config entity, and the services other modules may call. For
installation see `INSTALL.md`; for feature configuration see `README.md`.

> Stability: MCP Sentinel follows Semantic Versioning once a stable release is
> tagged. The seams below are the supported public surface; internal helpers
> (private/protected methods, trait internals) may change between minor versions.

## Events

### `McpDestructiveOpEvent` — veto a destructive operation

`Drupal\mcp_sentinel\Event\McpDestructiveOpEvent`
(event name: `McpDestructiveOpEvent::NAME` = `mcp_sentinel.destructive_op`).

Dispatched by the base module immediately before a governed destructive
operation (currently bulk delete) executes on a single entity — **after** all
access, policy, and lock checks have passed. A subscriber may call
`$event->veto($reason)` to stop the operation; the base module then records the
entity as queued and does **not** delete it. When no subscriber vetoes (the
common case — e.g. the approval submodule is absent), the event is a no-op and
the operation proceeds unchanged.

Accessors:

| Method | Returns |
|--------|---------|
| `getEntity()` | the target `EntityInterface` |
| `getOperation()` | the operation id (e.g. `'delete'`) |
| `getAccount()` | the acting `AccountInterface` |
| `veto(string $reason)` | mark the operation vetoed |
| `isVetoed()` | `bool` |
| `getVetoReason()` | the veto reason or `NULL` |

This is the exact seam the `mcp_sentinel_approval` submodule uses
(`McpDestructiveOpSubscriber`). Subscribe to it to add your own approval,
quota, or business-rule gate.

### `McpDestructiveActionEvent` — veto a non-entity destructive action

`Drupal\mcp_sentinel\Event\McpDestructiveActionEvent`
(event name: `McpDestructiveActionEvent::NAME` = `mcp_sentinel.destructive_action`).

The non-entity sibling of `McpDestructiveOpEvent`, for actions that have no
target entity — `config_import` (a governed config write), `module_disable`, and
`grant_mcp_admin` (break-glass elevation). It carries a target descriptor instead
of an `EntityInterface`: `getTargetType()` (e.g. `'config'`, `'module'`,
`'user'`), `getTargetId()`, `getOperation()`, `getAccount()`, and `getPayload()`;
the `veto()`/`isVetoed()`/`getVetoReason()` contract is identical. The approval
submodule's `McpDestructiveActionSubscriber` queues these for human approval and
`McpApprovalExecutor` replays them on approval.

```php
public static function getSubscribedEvents(): array {
  return [McpDestructiveOpEvent::NAME => 'onDestructiveOp'];
}

public function onDestructiveOp(McpDestructiveOpEvent $event): void {
  if ($this->shouldHold($event->getEntity(), $event->getAccount())) {
    $event->veto('Held by my custom gate.');
  }
}
```

### `McpEntityEvent` — observe governed entity changes (audit/webhook seam)

`Drupal\mcp_sentinel\Event\McpEntityEvent`
(event names: `mcp.entity.presave`, `mcp.entity.delete`).

Dispatched whenever a **governed** MCP operation creates, updates, or deletes an
entity. This is the extension point the reliable-webhook pipeline rides on: the
`McpEventDispatcher` service both fires this Symfony event and enqueues a
configured webhook delivery. Subscribe to stream governed changes into your own
SIEM, queue, or notification system without touching the audit log.

| Method | Returns |
|--------|---------|
| `getEntity()` | the changed `EntityInterface` |
| `getEventName()` | `'mcp.entity.presave'` or `'mcp.entity.delete'` |

> These events fire **only** for governed requests (resolved via the OAuth agent
> channel or the role fallback). Cookie-session admin changes do not dispatch
> them — matching the rest of Sentinel's governance model.

## Tool plugin contract

MCP Sentinel ships its governed tools as `tool` plugins
(`Drupal\tool\Attribute\Tool` on a class extending
`Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase`). They live in
`src/Plugin/tool/Tool/` and are discovered by core's Tool API; the
`mcp_sentinel_server` submodule registers them with `mcp_server`.

To build a tool that participates in Sentinel governance, use
`Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait`. It provides the
protected helpers the shipped tools share:

| Helper | Purpose |
|--------|---------|
| `denyReason(AccessResultInterface $result)` | extract a human-readable deny reason |
| `logDeniedAccess(...)` | write a `denied_access` audit row |
| `validationMessages(FieldableEntityInterface $entity)` | collect entity validation errors |
| `checkRateLimit(...)` | enforce the profile's per-window request rate limit |
| `applyResultCap(...)` | truncate a result list to the profile's `result_count_cap` |
| `checkResponseSizeCap(...)` | enforce the profile's response-size cap |
| `truncateBulkResultsToSizeCap(...)` | trim a bulk result set to the size cap |

`McpGovernedToolBase::checkAccess()` is final. It enforces the Drupal
permission, the shared connector-facing readiness contract, the exact OAuth
scope derived from the plugin definition, and the profile IP allowlist before
a subclass can run. A Tool that needs an additional restriction overrides
`checkGovernedAccess()` and may only narrow the common decision. Do not extend
`ToolBase` directly and do not reimplement this gate: doing so creates a path
that can operate when server/OAuth/audit/registration/identity/policy wiring is
absent.

## Policy-profile config entity

`Drupal\mcp_sentinel\Entity\McpPolicyProfile` implements
`Drupal\mcp_sentinel\McpPolicyProfileInterface`. A profile is the unit of
governance the resolver selects per request. Read its gates and limits via:

| Getter | Meaning |
|--------|---------|
| `getRoles()` | roles this profile applies to |
| `getWeight()` | selection weight (lowest wins on a tie) |
| `allowsRead()` / `allowsWrite()` / `allowsDelete()` | the read/write/delete gates |
| `allowsGraphqlMutations()` | GraphQL mutation gate |
| `getAllowedEntityTypes()` / `getDeniedEntityTypes()` | entity-type allow/deny lists |
| `getRedactedFields()` | field names redacted from read responses |
| `getRateLimitRequests()` / `getRateLimitWindow()` | rate-limit budget + window (seconds) |
| `getResultCountCap()` / `getResponseSizeCap()` | exfiltration caps (`0` = unlimited) |
| `getAllowedIps()` | per-profile CIDR allowlist (empty = no restriction) |
| `allowsConfigRead()` / `allowsConfigWrite()` | configuration read/write gates (both default off) |
| `getDeniedConfigTypes()` | config name-prefix denylist (deny always wins, e.g. `system.`) |
| `deniesPublish()` | publish gate — when `TRUE` (default) the agent cannot publish content |
| `getMaxModerationState()` | ceiling moderation state ID the agent may set (empty = no ceiling) |
| `getForbiddenRolePermissions()` | permissions a governed role must not hold (escape hatches; ships populated) |
| `getAcknowledgedRolePermissions()` | `role_id:permission` grants deliberately accepted, recorded in config |
| `allowsRawSql()` | raw-SQL gate for `mcp-sentinel:sql-query` (default off; see README → Raw SQL) |

Profiles are configuration entities, so they are exportable, deployable, and
overridable per environment. Do not store secrets in a profile — use Key
entities (see `INSTALL.md`).

## Configuration governance & publish gate

Beyond entity operations, a profile also governs **configuration** access and
content **publishing**. Both layers are additive and default to the safe value
(config off, publishing denied).

- **Config tools.** `mcp_sentinel_config_get`, `mcp_sentinel_config_list`, and
  `mcp_sentinel_config_set` are governed MCP tools registered with
  `drush mcp-sentinel:setup`. Each calls
  `McpAccessChecker::checkConfigAccess($name, $operation, $profile)` — the
  config counterpart to `checkEntityAccess()` — enforcing the master switch, IP
  allowlist, the `denied_config_types` prefix denylist (deny always wins), and
  the `allow_config_read` / `allow_config_write` gates. Reads/lists honor
  `audit_log_reads`; denied config names are never even enumerated by the list
  tool. When `mcp_server_oauth` is enabled, all three are additionally gated at
  the transport layer: config reads require **`mcp_config_read`**, config writes
  require **`mcp_config`** (never `mcp_write`). A content-tier token
  (`mcp_read` / `mcp_write`) is rejected before governance fires — config
  management is isolated to the auditor/dev/config tiers.
- **Hard-deny + audit on save.** `McpConfigSaveSubscriber` (on
  `ConfigEvents::SAVE`) audits every governed config save as `config_save` (diff
  via `McpAuditLogger::computeConfigDiff()`) and, for a governed write to a
  `denied_config_types` name, reverts the just-written value and throws a
  `ConfigException` — closing the bypass where a `TokenAuthUser` calls
  `Config::save()` directly without going through a tool.
- **Publish gate.** When `deniesPublish()` is `TRUE`, only the go-live transition
  is withheld — the gate is value-aware and shares one published-state check
  (`mcp_sentinel.moderation_gate` / `McpModerationGate::targetIsPublishedState()`)
  across both write paths: the `mcp_sentinel_workflow_transition` tool refuses a
  transition to a published state (and beyond `getMaxModerationState()`), and
  `hook_entity_field_access` forbids `edit` on `moderation_state` only when the
  *target* is a published state and on `status` only when set to `TRUE` — so the
  non-publish editorial transitions a role grants (`draft`, `submit_for_review`,
  `restore`, `archive`) and unpublishing are allowed. `hook_entity_presave` still
  forces unmoderated publishable entities unpublished. A human publisher publishes.

## Drush commands

| Command | Purpose |
|---------|---------|
| `mcp-sentinel:status` | Source-contract readiness plus policy, audit, lock, and config-guard state. Exits non-zero whenever the connector-facing source contract is not ready; a ready contract does not claim healthy posture, effective policy, or durable evidence. |
| `mcp-sentinel:role-audit` | Non-zero exit when a governed role holds a permission its profile forbids, or is an admin role. The deploy-time gate — run it after `config:import`. |
| `mcp-sentinel:sql-query <sql> [--profile=ID]` | The only governed raw-SQL path. Refused unless the resolved profile sets `allow_raw_sql` and `McpRawSqlGuard` accepts the statement; every attempt is written to the audit chain with its statement text. Exists because `drush sql:query` caps its bootstrap below module-command discovery and therefore cannot be governed by any Drupal module. |
| `mcp-sentinel:setup` | Register the MCP tools (incl. the config tools) with `mcp_server`. |
| `mcp-sentinel:agent-provision <tier> --env=<env>` | Idempotently provision a tier's role, dedicated agent account, and OAuth consumer (deterministic `client_id` = `<tier>-<env>`). Secrets stay a human action. |
| `mcp-sentinel:break-glass <uid>` | Raise an always-gated approval request to grant the time-boxed `mcp_admin` role (auto-revoked at `break_glass_ttl_seconds`). |

## Services

The base module exposes these services (`mcp_sentinel.services.yml`). They are
the supported PHP entry points for other modules:

| Service ID | Class | Use |
|------------|-------|-----|
| `mcp_sentinel.policy_resolver` | `McpPolicyResolver` | `isGoverned()` and `resolve(?AccountInterface)` → the active `McpPolicyProfile` or `NULL` |
| `mcp_sentinel.access_checker` | `McpAccessChecker` | entity/create access decisions, JSON:API filter access, `isClientIpAllowed()`, `checkConfigAccess()` |
| `mcp_sentinel.audit_logger` | `McpAuditLogger` | MCP policy in front of the shared chain: read-suppression, change diffs (`computeChangeDiff()` / `computeConfigDiff()`), redaction and DLP. Chain mechanics live in `audit_chain.logger`; write there directly if you want tamper-evident audit for something other than MCP traffic |
| `mcp_sentinel.event_dispatcher` | `McpEventDispatcher` | `dispatch($eventName, $entity)` — fires `McpEntityEvent` + enqueues webhooks |
| `mcp_sentinel.webhook_queue_manager` | `McpWebhookQueueManager` | enqueue/prune/requeue/replay webhook deliveries |
| `mcp_sentinel.oauth_context` | `McpOauthContext` | detect the OAuth agent channel (token + agent scope) |
| `mcp_sentinel.governance_readiness` | `McpGovernanceReadiness` | one typed source-contract decision shared by Tool/context/JSON:API/GraphQL, the authenticated readiness endpoint, settings, and Status report. `contractStatus()` proves local wiring only; `evaluate()` adds request designation/scope and can return not-applicable for ordinary Drupal traffic |
| `mcp_sentinel.dlp` | `McpDlp` | value-pattern redaction engine (email/phone/SSN/CC/custom) |
| `mcp_sentinel.rate_limiter` | `McpRateLimiter` | flood-backed per-profile rate limiting |
| `mcp_sentinel.exfiltration_guard` | `McpExfiltrationGuard` | result-count / response-size caps |
| `mcp_sentinel.raw_sql_guard` | `McpRawSqlGuard` | `check($sql, $profile)` → refusal reasons (`[]` = permitted). Resolves `denied_entity_types` and `redacted_fields` down to physical tables and columns via the entity table mapping; fail-closed on anything it cannot resolve |
| `mcp_sentinel.anomaly_detector` | `McpAnomalyDetector` | evaluate anomaly rules over the audit stream |
| `mcp_sentinel.anomaly_alert_dispatcher` | `McpAlertDispatcher` | dispatch log/email/webhook alerts for fired rules |
| `mcp_sentinel.content_lock` | `McpContentLock` | acquire/release/check short-lived content locks |
| `mcp_sentinel.metrics` | `McpMetrics` | governance-dashboard data; reads existing stores only, every audit/webhook query window-bounded |
| `mcp_sentinel.role_assertions` | `McpRoleAssertions` | `violations()` → governed roles holding forbidden permissions, resolving *effective* permissions (role ∪ `authenticated`) and treating `is_admin` as its own violation; `isAdminRole()` backs the forms' refusal to govern one |
| `mcp_sentinel.urgent_conditions` | `McpUrgentConditions` | `evaluate()` → critical/warning/info conditions + operator broadcast for the dashboard banner (pure read) |
| `mcp_sentinel.chart_renderer` | `McpChartRenderer` | `render($type, $series, $options)` → a `drupal/charts` element when `charts` is enabled, else an inline-SVG fallback (empty-state on empty series) |

### `McpReadBudgetResolver` — finite-by-default read budgets

`mcp_sentinel.read_budgets` resolves the effective budgets for a profile
(#3616540): a profile value of `0` clamps to
`mcp_sentinel.settings:read_budget_defaults` unless
`require_finite_read_budgets` is explicitly disabled (the non-production
override, surfaced as a status-report warning).

```php
$budgets = \Drupal::service('mcp_sentinel.read_budgets');
$cap = $budgets->effectiveResultCap($profile);        // int, 0 only under override
$bytes = $budgets->effectiveResponseSizeCap($profile); // int
[$requests, $window] = $budgets->effectiveRateLimit($profile);
[$pages, $pageWindow] = $budgets->pageBudget();
```

`McpExfiltrationGuard` and `McpRateLimiter` consume the resolver internally,
so Tool, JSON:API, GraphQL, and governed drush SQL channels share one budget
resolution.

### `McpMetrics` — governance-dashboard data

`mcp_sentinel.metrics` is the single read-only source of dashboard data. It
aggregates from existing stores only — `mcp_sentinel_audit_log`,
`mcp_sentinel_webhook_delivery`, approval entities (NULL-safe when the
submodule is absent), anomaly `@state`, and config. Every audit/webhook query is
**window-bounded** via the indexed `timestamp`/`created` columns and uses the
parameterized DB API; the `$window` argument is validated against a fixed
allowlist (`24h`/`7d`/`30d`, mapped to seconds) and defaults to `24h` for any
other value, so a caller can never inject an arbitrary bound. Each method is
defensive (a failing metric logs and returns a safe zero/empty value) and
results are statically cached per request.

Methods: `statusSummary()`, `auditCounts($window)`, `auditTimeSeries($window)`,
`allowedVsDenied($window)`, `operationMix($window)`, `topAgents($window, $limit = 5)`,
`deniedReasons($window)`, `webhookHealth($window)`, `approvalSummary()`,
`anomalySummary($window)`, `chainIntegrity()` (reads the stored last-verify
result from `@state`; never re-runs `verifyChain()` on the hot path), and
`activeControls()`.

### `McpUrgentConditions` — dashboard banner conditions

`mcp_sentinel.urgent_conditions` is a pure read-only evaluator. `evaluate()`
returns a list of `['severity', 'key', 'message', 'url']` entries for the
governance dashboard banner:

- `chain_broken` (critical) — the stored last-verify result in `@state`
  (`mcp_sentinel.last_verify`) is FALSE.
- `encryption_unresolvable` (critical) — an `audit_encryption_profile` is set
  but its EncryptionProfile or its Key cannot be resolved.
- `master_switch_off` (warning) — governance is OFF yet an agent audit row was
  written within the last 24 hours.
- `endpoint_key_unresolvable` (critical) — an enabled webhook endpoint's
  `secret_key` does not resolve via the Key repository.
- `operator_broadcast` (config severity) — the `dashboard_broadcast` message is
  non-empty.

`severity` is one of `info`/`warning`/`critical`; `url` is an internal path to
the relevant settings/audit route (or NULL). It performs no writes.

### `McpChartRenderer` — dashboard charts (optional drupal/charts upgrade)

`mcp_sentinel.chart_renderer` turns a metric series into a render array via
`render(string $type, array $series, array $options = [])` (`$type` is
`bar`/`line`/`donut`/`pie`; `$options` accepts `title` and `drill_url`). It
isolates the optional `drupal/charts` contrib dependency to a single place:
when the `charts` module is enabled it returns a `#type => 'chart'` element;
otherwise it returns a self-contained inline-SVG/CSS fallback (no JavaScript).
An empty series returns an empty-state ("No data") build. `drupal/charts` is a
composer `suggest` only — it is never a hard requirement or an info.yml
dependency.

### `McpDashboardController` — governance dashboard

`McpDashboardController::dashboard(Request $request)` serves the governance
dashboard at route `mcp_sentinel.dashboard` (`GET /admin/reports/mcp-sentinel`,
permission *View MCP Sentinel audit log*). It is read-only: it assembles a
themed render array (`#theme => 'mcp_sentinel_dashboard'`) from the three data
services — the urgent banner (`McpUrgentConditions`), the posture hero, status
tiles, chain-integrity card, top-agents / denied-by-policy panels,
quick-actions, and active-controls strip (`McpMetrics`). The `?window=` query
parameter is validated to `24h`/`7d`/`30d` (default `24h`). Each widget is
built behind its own try/catch so a single failing metric degrades to an
empty/"—" widget (logged to `mcp_sentinel`) rather than fataling the page. The
six charts are produced via `McpChartRenderer`, and chart/tile click-to-drill
links target the filtered audit (and webhook) logs.

`McpDashboardController::verify()` backs the route `mcp_sentinel.verify_chain`
(`GET /admin/reports/mcp-sentinel/verify`, permission *Administer MCP Sentinel
settings*, **CSRF-protected** via `_csrf_token: TRUE`). It re-runs
`McpAuditLogger::verifyChain()`, writes the outcome to `@state`
`mcp_sentinel.last_verify` in the SAME shape the `drush
mcp-sentinel:audit-verify` command writes (`ok`, `broken_at`, `rows`, `time`),
then redirects to the dashboard with a status message.

When the audit listing moved to `/admin/reports/mcp-sentinel/audit`, the route
name `mcp_sentinel.audit_log` and the `mcp_sentinel.audit_export` route were
left unchanged, so existing deep links and the filter form's reset link follow
the new path automatically.

### Resolving governance in your own code

```php
$resolver = \Drupal::service('mcp_sentinel.policy_resolver');
if ($resolver->isGoverned()) {
  $profile = $resolver->resolve();
  if ($profile !== NULL && !$profile->allowsWrite()) {
    // The current governed agent is denied write.
  }
}
```

`resolve()` returns `NULL` for ungoverned (e.g. cookie-session admin) requests —
always treat `NULL` as "not governed, do nothing", never as "deny".

## Hooks implemented by the module

For reference, MCP Sentinel governs the request stack through these core hooks
(in `mcp_sentinel.module`): `hook_entity_presave`, `hook_entity_delete`,
`hook_entity_access`, `hook_entity_create_access`, `hook_entity_field_access`
(redaction), `hook_jsonapi_entity_filter_access`, `hook_cron` (prune + anomaly),
`hook_mail` (anomaly email), `hook_help`, `hook_theme` (the dashboard and
urgent-banner templates), and `hook_page_top` (the site-wide critical urgent
banner). The `mcp_sentinel_graphql` submodule adds a
`graphql_compose_field_results_alter` hook for GraphQL redaction, DLP, and
result caps.

## Dashboard-support routes

Two helper routes back the dashboard UI (neither is a public API surface, but
both are listed here for completeness):

- `mcp_sentinel.banner_dismiss` (`/admin/reports/mcp-sentinel/banner-dismiss`,
  permission *View MCP Sentinel audit log*, CSRF-protected) — records a per-user
  dismissal of the site-wide critical banner (`McpBannerController::dismiss()`,
  private tempstore). The banner reappears while the condition still holds.
- `mcp_sentinel.webhook_prune` (`/admin/reports/mcp-sentinel/webhooks/prune`,
  permission *Administer MCP Sentinel settings*, CSRF-protected) — the inline
  prune action on the webhook delivery log
  (`McpWebhookDeliveryController::prune()`), equivalent to
  `drush mcp-sentinel:webhook-prune`.
