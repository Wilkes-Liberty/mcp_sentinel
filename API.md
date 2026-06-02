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
`Drupal\tool\Tool\ToolBase`). They live in `src/Plugin/tool/Tool/` and are
discovered by core's Tool API; the `mcp_sentinel_server` submodule registers
them with `mcp_server`.

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

A governed tool's `checkAccess()` should resolve the account's profile via
`mcp_sentinel.policy_resolver`, and when governed, enforce the IP allowlist
(`McpAccessChecker::isClientIpAllowed()`) returning
`AccessResult::forbidden()->setCacheMaxAge(0)` on failure — the canonical
pattern used by every shipped write tool. Ungoverned accounts must be left
unaffected (return neutral). The shipped `McpContentLockTool` is the reference
implementation.

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

Profiles are configuration entities, so they are exportable, deployable, and
overridable per environment. Do not store secrets in a profile — use Key
entities (see `INSTALL.md`).

## Services

The base module exposes these services (`mcp_sentinel.services.yml`). They are
the supported PHP entry points for other modules:

| Service ID | Class | Use |
|------------|-------|-----|
| `mcp_sentinel.policy_resolver` | `McpPolicyResolver` | `isGoverned()` and `resolve(?AccountInterface)` → the active `McpPolicyProfile` or `NULL` |
| `mcp_sentinel.access_checker` | `McpAccessChecker` | entity/create access decisions, JSON:API filter access, `isClientIpAllowed()` |
| `mcp_sentinel.audit_logger` | `McpAuditLogger` | write/read the tamper-evident, hash-chained, optionally encrypted audit log; `computeChangeDiff()` |
| `mcp_sentinel.event_dispatcher` | `McpEventDispatcher` | `dispatch($eventName, $entity)` — fires `McpEntityEvent` + enqueues webhooks |
| `mcp_sentinel.webhook_queue_manager` | `McpWebhookQueueManager` | enqueue/prune/requeue/replay webhook deliveries |
| `mcp_sentinel.oauth_context` | `McpOauthContext` | detect the OAuth agent channel (token + agent scope) |
| `mcp_sentinel.dlp` | `McpDlp` | value-pattern redaction engine (email/phone/SSN/CC/custom) |
| `mcp_sentinel.rate_limiter` | `McpRateLimiter` | flood-backed per-profile rate limiting |
| `mcp_sentinel.exfiltration_guard` | `McpExfiltrationGuard` | result-count / response-size caps |
| `mcp_sentinel.anomaly_detector` | `McpAnomalyDetector` | evaluate anomaly rules over the audit stream |
| `mcp_sentinel.anomaly_alert_dispatcher` | `McpAlertDispatcher` | dispatch log/email/webhook alerts for fired rules |
| `mcp_sentinel.content_lock` | `McpContentLock` | acquire/release/check short-lived content locks |
| `mcp_sentinel.metrics` | `McpMetrics` | governance-dashboard data; reads existing stores only, every audit/webhook query window-bounded |

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
`hook_mail` (anomaly email), and `hook_help`. The `mcp_sentinel_graphql`
submodule adds a `graphql_compose_field_results_alter` hook for GraphQL
redaction, DLP, and result caps.
