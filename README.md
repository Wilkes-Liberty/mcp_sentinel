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

See also: [`INSTALL.md`](INSTALL.md) for step-by-step installation, dependency,
and reverse-proxy setup; [`API.md`](API.md) for the events, Tool plugin
contract, policy-profile entity, and services other modules can extend.

## Trust model

Governance triggers on the **validated OAuth agent channel** — the consumer and
token scopes on the request's access token, as resolved by Simple OAuth — never
on a request header. A request is "governed" when it arrives on a configured
agent OAuth client/scope, or (as a configurable local-dev fallback,
`governed_role_fallback`, default `false`) when its authenticated account holds
one of the configured *governed roles* (default: the `mcp_api` role created on
install). An admin's direct cookie-session Drupal UI is never governed. The
`X-MCP-Client` header is at most a log hint — an agent cannot bypass policy by
omitting it, and a non-agent user cannot be governed by adding it. The
`anonymous` and `authenticated` roles can never be governed.

Each governed agent is matched to an **`mcp_policy_profile`** (the highest-weight
enabled profile whose roles it holds, else the shipped `default` profile), which
defines its operation gates, entity allow/deny lists, and redacted fields. Manage
profiles at **Configuration → Web services → MCP Sentinel → MCP policy profiles**.

> **Scope-name convention & fail-loud guard.** The `agent_scopes` you configure
> must match your `oauth2_scope` machine-ids exactly. simple_oauth scope
> machine-ids are conventionally underscore-separated, so fresh installs ship
> `agent_scopes: [mcp_read, mcp_write, mcp_config, mcp_config_read]`; align this
> with your actual scope ids. (`mcp_config_read` is the read-only config scope the
> `config_get`/`config_list` tools require — grant it to a read-only auditor or a
> dev/config consumer; `mcp_config` is the config *write* scope `config_set`
> requires — grant it only to a dev/config consumer.)
> **A profile governs the channel, not the role.** A policy profile constrains
> what the agent may do *through MCP*. It says nothing about what the governed
> Drupal role may do outside it — and a role holding `bypass file gate` fetches
> gated private files straight off `/system/files/…` with no MCP request, so no
> policy, no redaction and no audit row. Each profile therefore also asserts
> which permissions its governed roles must **not** hold; see
> [Escape-hatch permission assertions](#escape-hatch-permission-assertions).
> **What governance does not cover: shell access to the server.** Everything
> above governs requests that reach Drupal. A process with SSH access to the
> web server does not make requests — it runs `drush`, and most Drush commands
> never load Drupal's module system at all. `drush sql:query` is the clearest
> case: it declares a bootstrap ceiling below the level at which module command
> files are discovered, so no hook, subscriber or policy check in *any* Drupal
> module can fire for it. The same is true of `sql:cli`, `sql:dump` and
> `php:eval`. This is a property of Drush, not a gap this module can close: an
> entity type on `denied_entity_types` is still readable through raw SQL by
> anything holding the SSH key. Treat the shell as an **operator** channel,
> keep the agent's credentials off it, and constrain it there — the companion
> connector's per-site `allowedCommands` is the control. For the one case where
> an agent genuinely needs to read with SQL, see
> [Raw SQL](#raw-sql-opt-in-governed-and-recorded) below.
>
> A governance module should never be a silent no-op, so when the module is
> **enabled but cannot govern any request** — both `agent_scopes` and
> `agent_oauth_clients` empty (with the role fallback unusable), or no policy
> profile configured — the status report (**Reports → Status report**) raises a
> WARNING, "MCP Sentinel: not governing any request". Fix the warning before
> relying on governance; until then the module is failing open.

## Requirements

- Drupal 10.6+ or 11.3+
- **PHP 8.3+.** Two independent reasons, either sufficient on its own: the module's
  own code uses typed class constants, which are 8.3 syntax and a parse error below
  it; and `drupal/simple_oauth` is a runtime dependency whose chain
  (`league/oauth2-server`, `lcobucci/jwt`) requires 8.2 or newer. A Drupal 10.6 site
  on PHP 8.1 or 8.2 cannot run this module, even though 10.6 itself supports those.
- [Tool API](https://www.drupal.org/project/tool) (`drupal/tool`)
- [Key](https://www.drupal.org/project/key) (`drupal/key`) — stores the webhook
  signing secret and (optionally) the audit encryption key outside exported
  configuration
- [Encrypt](https://www.drupal.org/project/encrypt) (`drupal/encrypt`) —
  provides Encryption Profiles for at-rest encryption of audit metadata; the
  package is a required dependency (listed in `composer.json` and `info.yml`),
  though the encryption feature is opt-in and configured via settings
- [Simple OAuth](https://www.drupal.org/project/simple_oauth) (`drupal/simple_oauth`)
  and [Consumers](https://www.drupal.org/project/consumers) (`drupal/consumers`) —
  the validated OAuth agent channel governance triggers on
- **Strongly recommended:** [MCP Server](https://www.drupal.org/project/mcp_server)

> **Why `composer.json` keeps `minimum-stability: dev`.** Every hard runtime
> dependency is a stable, tagged release, and `prefer-stable: true` keeps your
> install on stable wherever one exists. The single exception is the
> *development-only* dependency `drupal/mcp_server`, which has **no tagged stable
> release** yet (`^2.0@dev`). Pulling it for the `mcp_sentinel_server`
> integration tests therefore requires `minimum-stability: dev`. This does not
> loosen production installs — `mcp_server` is in `require-dev`, never `require`.
> When `mcp_server` ships a stable tag, the dev constraint can be pinned and
> `minimum-stability` dropped.

## Installation

```bash
composer require drupal/mcp_sentinel drupal/mcp_server drupal/simple_oauth

# Enable the base module plus the production MCP integration and OAuth gate.
drush en mcp_sentinel mcp_sentinel_server mcp_server_tool_bridge mcp_server_oauth -y
drush cr

# Register every Tool with required OAuth and its exact derived scope.
drush mcp-sentinel:setup

# Bind one environment-specific Consumer to an active role/profile.
drush mcp-sentinel:agent-provision content --env=prod
```

`mcp-sentinel:setup` is fail closed: production OAuth is required by default,
all registrations are preflighted before the first save, and partial writes are
rolled back. It returns non-zero until an applicable designated Consumer has
been provisioned. The only unauthenticated escape is the explicit
`--allow-unauthenticated-development` option; it always returns non-zero and can
never make `/drupal-mcp/readiness` report `contract_ready`.

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
| `mcp_sentinel_server` | Registers the Tool plugins with mcp_server (`mcp_tool_config` entities), requires per-Tool OAuth on production paths, and provisions designated Consumers. Provides `drush mcp-sentinel:setup` / `:teardown` / `:agent-provision`. Depends on `mcp_server_tool_bridge`; production readiness also requires `mcp_server_oauth`. |
| `mcp_sentinel_graphql` | Extends governance to the GraphQL endpoint: gates mutations/reads, redacts fields, and audits operations for governed agents. Depends on `graphql_compose`. |
| `mcp_sentinel_approval` | Optional human-approval gate: queues governed destructive operations (bulk delete) as approval requests instead of executing them, for an authorized human to approve or deny. Depends only on `mcp_sentinel`. |

### Approval workflow (`mcp_sentinel_approval`)

When enabled, governed **destructive** operations (currently the bulk-delete
path) are not executed immediately. Instead the base bulk tool dispatches a
veto-capable `McpDestructiveOpEvent`; this submodule's subscriber records a
pending `mcp_approval_request` and vetoes execution, so the entity is left
intact and reported back to the agent as *queued for approval*.

An operator with the **Approve MCP Sentinel operations** permission reviews the
queue at `/admin/reports/mcp-sentinel/approvals` and approves or denies each
request. Approving replays the stored operation (re-checking the approver's own
delete access), marks the request approved, and writes an `approval_decision`
row to the audit log; denying records the denial and leaves the target intact.

Which operations are gated is configurable via the
`mcp_sentinel_approval.settings:gated_operations` key (default: `[delete]`).
The base module has **no dependency** on this submodule — with the submodule
absent, the event is never vetoed and destructive operations proceed unchanged.

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
| Configuration read/write governance + denylist | ❌ | ✅ |
| Publish gate (agent content lands unpublished) | ❌ | ✅ |
| Time-boxed `mcp_admin` break-glass | ❌ | ✅ |
| Field-level PII redaction | ❌ | ✅ |
| DLP value-pattern redaction / masking | ❌ | ✅ |
| Audit log | ❌ | ✅ |
| Filterable audit UI + CSV/JSON export | ❌ | ✅ |
| Redaction-aware change diffs | ❌ | ✅ |
| Tamper-evident audit hash chain | ❌ | ✅ |
| At-rest audit metadata encryption | ❌ | ✅ |
| SIEM streaming | ❌ | ✅ |
| Content locks | ❌ | ✅ |
| Per-profile rate limiting & quotas | ❌ | ✅ |
| Exfiltration guards (result/size/page caps) | ❌ | ✅ |
| Per-profile IP allowlisting | ❌ | ✅ |
| Anomaly detection & alerting | ❌ | ✅ |
| Reliable queued webhooks (retry/replay/SSRF guard) | ❌ | ✅ |
| Human approval workflow (submodule) | ❌ | ✅ |
| Rich context endpoint | ❌ | ✅ |
| mcp_api role | ❌ | ✅ |

## Configuration governance & publish gate

Beyond entity CRUD, a policy profile also governs **configuration** and content
**publishing**. Both are additive and default to the safe value — config read
and write are off, and publishing is denied — so upgrading changes no behavior
until you opt a profile in at **Configuration → Web services → MCP Sentinel →
MCP policy profiles → Configuration governance**.

- **Config tools.** Enable governed `config get` / `list` / `set` by running
  `drush mcp-sentinel:setup` (it registers the three new tools). Access is gated
  by `allow_config_read` / `allow_config_write` and a `denied_config_types`
  name-prefix denylist (deny always wins). A `ConfigEvents::SAVE` subscriber
  audits every governed config save and hard-denies (revert + throw) a governed
  write to a denied config name, so a direct `Config::save()` cannot bypass it.
- **Publish gate.** When *Deny publishing* is on (the default), only the
  **go-live** transition is withheld from the agent — the gate is value-aware, so
  the non-publish editorial transitions a role grants (`draft`,
  `submit_for_review`, `restore`, `archive`) are permitted while a transition to a
  *published* state is refused. This holds on **both** write paths: the
  workflow-transition tool and the JSON:API/REST write path (the
  `moderation_state` / `status` field-access gate), which share one
  published-state check (`mcp_sentinel.moderation_gate`). An optional maximum
  moderation state still applies. On unmoderated publishable entities the
  `status` flag is blocked in the publish direction, and an in-place edit of
  **already-published** unmoderated content never mutates the live revision:
  revisionable types store the edit as an unpublished forward revision for a
  human to review, and types that cannot carry a forward revision are refused
  (unpublishing — takedown — remains allowed in place). A human `publisher`
  publishes.
- **Write preconditions.** Every governed mutation of an existing entity —
  including relationship-only writes, translations, and deletes — runs one
  shared precondition contract before anything changes: an active content lock
  held by a *different* server-resolved principal denies the write and the
  delete (the acting principal's own lock never blocks it), and a save that
  would replace the stored default revision from a copy of it that is no
  longer current is refused instead of overwriting the concurrent change
  (continuing a forward — non-default — draft is not affected). Validated
  seams (JSON:API, REST, forms)
  report a 422; unvalidated saves abort with a rollback-surviving evidence
  row, and passing updates record the checked precondition and final target
  revision on their audit row. Ungoverned human traffic is never gated.
- **Per-entity-type destructive overrides.** A profile's global `allow_delete`
  (and `allow_write`) flag is the default for every entity type, but an
  `entity_rules` map can override it for one type at a time. Setting
  `entity_rules.taxonomy_term.allow_delete: true` on a profile whose global
  `allow_delete` is `false` lets the agent delete **taxonomy terms only** — node,
  media, paragraph, menu, redirect, file, and every other type stay
  delete-denied. The effective rule is `entity_rules[type].allow_delete ??
  allow_delete`. This is the *Sentinel* gate; the Drupal role permission
  (e.g. `delete terms in <vocabulary>`) remains an independent second gate, so a
  delete requires **both**. Edit the per-type delete overrides at **MCP policy
  profiles → Allowed operations → Per-entity-type delete overrides** (one entity
  type machine name per line); the effective map is reported by
  `mcp_sentinel_security_policy` (and the connector's `drupal_security_info` as
  `entityRules`).
- **Approval for config/admin ops** (with the approval submodule):
  `gated_operations` defaults to `delete`, `config_import`, `module_disable`.
  Tier provisioning is one command: `drush mcp-sentinel:agent-provision <tier>
  --env=<env>`. The `mcp_admin` role is never standing — request it with
  `drush mcp-sentinel:break-glass <uid>`, which raises an approval; on approval
  it is granted for `break_glass_ttl_seconds` and auto-revoked on cron. The role
  is a non-admin, five-permission operator break-glass set (not superuser); grants
  refuse if the role is missing, `is_admin`, or holds permissions outside that
  allowlist. Status report ERROR/WARNING mirrors that posture. Agent capability
  changes stay on the policy profile, not this role.

**Upgrade note.** The new profile fields are added at their safe defaults by an
update hook (`drush updatedb`); run `drush mcp-sentinel:setup` to expose the
config tools, and `drush cr`. No existing behavior changes until a profile opts
in.

## Tamper-evident audit log

> **The chain itself lives in [Audit Chain](https://www.drupal.org/project/audit_chain)**
> (`drupal/audit_chain`), a required dependency since 1.14. Hashing, HMAC
> signing, at-rest encryption and verification are its job; MCP Sentinel is the
> policy in front of it and writes under the `mcp_sentinel` channel. If you want
> tamper-evident audit for something that has nothing to do with AI agents —
> personnel-record reads, permission grants, break-glass logins — depend on
> Audit Chain directly rather than on this module.


Every audit row stores a `prev_hash` and a `row_hash` (a hash of the prior row's
hash concatenated with a canonical JSON of this row's content). The hash is
HMAC-SHA256 when `audit_hash_key` is set to a Key entity ID (use a File or
Environment key provider so the secret never appears in exported config), and
plain SHA-256 as a zero-config fallback. The canonical also covers the forensic
columns `entity_label`, `ip_address`, and `user_agent`, so inserting, deleting,
or editing any historical row — including those columns — breaks the chain.

Verify the chain at any time:

```bash
drush mcp-sentinel:audit-verify
```

The command exits 0 if the chain is intact, non-zero (and prints the first
broken row id) if tampering is detected. Run `update_10003` (via
`drush updb`) to add the `prev_hash`/`row_hash` columns to an existing install.
New rows written after the update are automatically chained; rows written before
the update have NULL hashes and are skipped by the verifier.

## Audit metadata encryption at rest

MCP Sentinel can encrypt the `metadata` column of every audit row using
[drupal/encrypt](https://www.drupal.org/project/encrypt) Encryption Profiles.

### Setup

1. Install and enable drupal/encrypt: `composer require drupal/encrypt && drush en encrypt -y`.
2. Create a Key entity at **Configuration → System → Keys** (use a File or
   Environment key provider so the secret never appears in exported config).
3. Create an Encryption Profile at
   **Configuration → System → Encryption → Encryption Profiles**, pointing it
   at the key you just created.
4. In the MCP Sentinel settings form (**Configuration → Web services →
   MCP Sentinel**), open the *Audit Logging* tab and choose your Encryption
   Profile from the *Audit metadata encryption profile* select.
5. Save the form. New audit rows will be encrypted; existing plaintext rows
   remain readable (decryption failure falls back to plain JSON decode, so no
   data migration is needed).

### Hash chain and encryption

The tamper-evident hash chain hashes **plaintext** canonical content before
encryption occurs. This means `drush mcp-sentinel:audit-verify` continues to
work correctly regardless of key rotation or profile changes — only the stored
column is encrypted; the canonical used for hashing is always plaintext.

## SIEM streaming

When the *Enable SIEM streaming* checkbox is checked in the Audit Logging
settings, every successful audit write emits an `info`-level record to the
dedicated `mcp_sentinel_audit` logger channel. The structured context array
contains: `operation`, `uid`, `entity_type`, `bundle`, `entity_id`,
`timestamp`, and `row_hash` (which ties the SIEM record back to the hash-chain
entry in the database).

To route this channel to a SIEM, enable syslog output via the **core Syslog
module** (no additional composer packages required):

```yaml
# Example: enable the Syslog module and configure the facility.
drush en syslog -y
```

With Syslog enabled, all Drupal log channels (including `mcp_sentinel_audit`)
are written to the system log; your log-shipping agent (Filebeat, Fluentd,
etc.) can then forward them to your SIEM.

For finer-grained control — e.g. writing only the audit channel to a dedicated
file or sending it to a remote aggregator — use
[`drupal/monolog`](https://www.drupal.org/project/monolog). Define a handler
for the `mcp_sentinel_audit` channel in your `monolog.services.yml` and route
it to syslog, Logstash, or any other Monolog handler.

## DLP value-pattern redaction (opt-in)

Beyond field-name redaction, MCP Sentinel can scan the **values** of governed
field output for PII patterns and either fully redact or partially mask matches.
DLP scanning is **off by default** and must be explicitly enabled.

### Setup

1. Go to **Configuration → Web services → MCP Sentinel** and open the
   *Data Loss Prevention (DLP)* tab.
2. Check *Enable DLP value-pattern scanning*.
3. Choose the *Mask mode*:
   - **Redact** — replaces the full match with `[REDACTED]`.
   - **Partial** — keeps the last 4 characters of the match and replaces the
     rest with `*` (e.g. `************4567` for a 16-digit credit-card number).
4. Save. DLP takes effect immediately for new governed requests.

### Built-in patterns

Four patterns are pre-configured (all disabled by default via `dlp_enabled:
false`):

| Label | Matches |
|-------|---------|
| `email` | RFC-5321 email addresses |
| `us_phone` | US phone numbers (dashes, dots, spaces, parentheses) |
| `ssn` | US Social Security Numbers (`NNN-NN-NNNN`) |
| `credit_card` | 16-digit card numbers in 4-group format (dashes or spaces) |

### Adding custom patterns

Operators can configure custom patterns directly from the settings form's
*Data Loss Prevention (DLP)* tab:

1. Go to **Configuration → Web services → MCP Sentinel** and open the *Data Loss
   Prevention (DLP)* tab.
2. Enable DLP, then use the **Custom DLP patterns** editor. Each pattern is its
   own row with separate **Label**, **Pattern (regex)**, and **Mask** fields
   (`mask` is optional and defaults to `*`). Use **Add pattern** to add a row and
   **Remove pattern N** to drop one. For example, add two rows:

   | Label | Pattern (regex) | Mask |
   |-------|-----------------|------|
   | `employee_id` | `EMP-\d{6}` | `*` |
   | `internal_ref` | `CUST-\d{8}` | |

3. Save. Invalid regex rows are rejected with a validation error before saving.

Leaving every row blank clears any custom patterns and falls back to the four
built-in defaults (email, US phone, SSN, credit card) at runtime.

Custom patterns can also be managed directly in `mcp_sentinel.settings.yml`:

```yaml
dlp_patterns:
  - label: my_pattern
    regex: 'CUST-\d{8}'
    mask: '*'
```

**Regex convention:** store the PCRE pattern body **without** delimiters. The
service wraps each pattern in `#...#i` at runtime (case-insensitive, `#`
delimiter avoids escaping `/` in URLs). Do **not** include leading or trailing
`/` or `#` characters in the `regex` value. Invalid patterns are silently
skipped with a warning logged to the `mcp_sentinel` logger channel so a
badly-formed custom regex cannot cause a fatal error.

### V1 scope

DLP scanning is wired into two output paths:

1. **GraphQL Compose field output** (`mcp_sentinel_graphql` submodule): string
   field values returned by `hook_graphql_compose_field_results_alter` are
   scanned before delivery to the agent.
2. **Audit change-diff capture** (`McpAuditLogger::computeChangeDiff`): field
   values in the `changes` diff stored in audit log metadata are masked before
   storage, so PII never appears in the audit trail in plaintext.

JSON:API and REST per-field value scanning is deferred to a future release.
Drupal core's normalizer stack has no stable per-value alter hook, so a clean
wiring point does not yet exist.

## Rate limiting & quotas

MCP Sentinel can throttle governed agent traffic on a per-profile basis using
Drupal's core flood service. Limits apply per authenticated user account within
each policy profile window, so a single compromised token cannot saturate the
server.

### Setup

1. Go to **Configuration → Web services → MCP Sentinel → MCP policy profiles**
   and edit the target profile.
2. In the *Rate limits & quotas* tab:
   - **Max requests per window** — maximum governed tool calls allowed in the
     window. `0` no longer means unlimited: it resolves to the finite default
     budget (see *Finite-by-default read budgets* below).
   - **Window (seconds)** — the rolling window duration. Default is `60`.
3. Save. The limit takes effect immediately for new requests.

### Recommended starting point for production

`300` requests per `60` second window is a reasonable baseline for most sites.
Adjust based on observed agent traffic patterns.

### How it works

- The flood key is `mcp_sentinel.profile.{profile_id}.{uid}` where `{uid}` is
  the server-resolved authenticated user ID — never an agent-supplied value.
  This prevents key-cycling bypass attacks.
- A limit of `0` resolves to the finite default request budget unless the
  explicit non-production override is active, in which case it short-circuits
  before touching the flood service (#3616540).
- When the limit is exceeded, governed tool calls return a "rate limit exceeded"
  failure and an audit row is written with operation `rate_limit_exceeded`.
  Enforcement is applied at the top of each governed tool's execution, before
  any business logic.

## Exfiltration guards / quotas

MCP Sentinel caps the volume of data a governed agent can retrieve in a single
call, preventing mass-read attacks and accidental data exfiltration.

### Setup

1. Go to **Configuration → Web services → MCP Sentinel → MCP policy profiles**
   and edit the target profile.
2. In the *Rate limits & quotas* tab:
   - **Max result items** — maximum items returned per Tool call, JSON:API page
     request, or GraphQL multi-value field result list. `0` resolves to the
     finite default (500) rather than unlimited. Recommended: `500`.
   - **Max response size in bytes** — maximum serialized response size for
     governed responses. Bulk-write Tool output exceeding this limit is
     truncated after the writes complete (with `_size_truncated: true`
     flagged); pure-read tools fail before materializing data; over-budget
     JSON:API/GraphQL responses are refused with a 413. `0` resolves to the
     finite default (8 MiB). Recommended: `2097152` (2 MB).
3. Save. Limits take effect immediately.

### Enforcement seams

| Seam | How caps are applied |
|------|----------------------|
| **Tool output** | `McpBulkOperationsTool` truncates `succeeded` list to `result_count_cap`; adds `_result_truncated: true` + `_result_cap` to the result data. The response-size cap is measured on the serialized payload and truncates post-write output (`_size_truncated: true`) rather than failing a completed batch. |
| **JSON:API** | A `KernelEvents::REQUEST` subscriber blocks `page[limit]` values above `result_count_cap` for governed requests with HTTP 400 before the DB query runs. (`hook_jsonapi_resource_params_alter` does not exist in Drupal 11.3; the subscriber is the correct implementation.) |
| **GraphQL** | `hook_graphql_compose_field_results_alter` in `mcp_sentinel_graphql` truncates multi-value field result lists to `result_count_cap` as a third pass after redaction and DLP masking. |

| **Response bytes** | `McpGovernedResponseSubscriber` measures every governed JSON:API/GraphQL response and replaces an over-budget body with a bounded 413 refusal (`response_size_cap_exceeded`) plus a non-sensitive audit row. |

Ungoverned requests are never capped. A profile cap of `0` is clamped to the
finite defaults unless the explicit override is active (next section).

## Finite-by-default read budgets (#3616540)

Unlimited is not an exfiltration floor. Since this feature, every governed
read budget is finite by default: a profile value of `0` resolves to the
defaults in `mcp_sentinel.settings`:

```yaml
require_finite_read_budgets: true
read_budget_defaults:
  results: 500        # max items per request
  bytes: 8388608      # max response bytes (8 MiB)
  requests: 600       # max governed requests per window
  request_window: 60
  pages: 120          # max collection pages per window
  page_window: 60
```

An explicit finite profile value always wins — the requirement is that every
budget is *finite*, not small. On the governed JSON:API seam this also means:

- every governed request consumes the per-principal request budget (429
  `read_budget_exceeded` when exhausted) — the source-side chained-action
  floor;
- collection reads consume a windowed per-principal page budget (429
  `page_budget_exceeded`), so pagination cannot amplify a bounded per-request
  cap into an unbounded export;
- an absent `page[limit]` is pinned to a finite cap smaller than JSON:API's
  default page size of 50, so omitting the parameter never reads more rows
  than requesting the maximum.

Budget denials write bounded, non-sensitive `read_budget_denied` audit rows
(budget class, profile, path, sizes — never payloads).

Setting `require_finite_read_budgets: false` is the **explicit non-production
override**: it restores the historical `0 = unlimited` behavior and raises a
permanent warning on the status report, so a secure-install verification can
never report clean while the override is active.

## Evidence-required actions (#3616539)

For most operations an audit row is a record of what happened. For a
high-assurance action class, that is backwards: the evidence is a
*precondition*, and an action whose evidence cannot commit must not run at
all. Marking a class in a profile's `evidence_required_actions` (empty by
default; `entity_write` and `entity_delete` are the supported classes) turns
that contract on for the principals the profile governs:

- **The veto.** Before the mutation, the guard verifies evidence can commit:
  the audit chain module is installed, auditing is enabled, and the chain's
  configured signing key resolves. Any miss refuses the action with a stable
  reason code (`evidence_chain_missing`, `evidence_audit_disabled`,
  `evidence_unkeyed`) and a rollback-surviving `evidence_veto` row. No
  fallback to unkeyed integrity or best-effort logging satisfies the class —
  an unsigned chain proves nothing against a writer who can recompute it.
- **Atomic co-commit.** The `evidence_precommit` row (correlation id,
  principal, policy digest, decision, target) is appended inside the same
  transaction as the mutation: both become durable together or neither does.
  An evidence-store outage aborts the save; a save that fails after its
  precommit takes the precommit down with it. There is no reachable state in
  which the mutation persists without its evidence.
- **Receipts and explicit uncertainty.** The post-save `entity_save` /
  `entity_delete` row is the execution receipt, completing the precommit's
  correlation id. If a receipt fails when the mutation is already durable
  (a non-transactional path), the outcome is recorded once per correlation id
  in a reconciliation ledger and refused to the caller as
  `evidence_uncertain` — never reported as a proven success. Cron retries the
  ledger; reconciled receipts are appended marked `reconciled`, and pending
  entries raise a status-report error until they drain.

## IP allowlisting per profile

Each policy profile can restrict governed agent connections to a specific set of
IPv4/IPv6 addresses and CIDR blocks. An **empty list** means *no restriction* —
any source IP is permitted.

### Setup

1. Go to **Configuration → Web services → MCP Sentinel → MCP policy profiles**
   and edit the target profile.
2. In the *Network / IP* tab, enter one address or CIDR block per line. Both
   IPv4 and IPv6 are supported:
   ```
   203.0.113.0/24
   198.51.100.42
   2001:db8::/32
   ```
3. Save. The allowlist takes effect immediately for new governed requests. To
   remove all IP restrictions, clear the textarea.

### How it works

The IP check is centralized in `McpAccessChecker::isClientIpAllowed()` — a
single canonical implementation used by all governed paths. Enforcement covers:

| Path | Gate |
|---|---|
| **Entity access** (`hook_entity_access`) | `McpAccessChecker::checkEntityAccess()` — first check after the global enabled flag, before entity-type / operation gates. Covers JSON:API, GraphQL, and REST entity reads and writes on **existing** entities (view/update/delete). |
| **Entity create access** (`hook_entity_create_access`) | `McpAccessChecker::checkCreateAccess()` — `hook_entity_access` does not fire for CREATE, so JSON:API `POST` (new entity) is gated here. Enforces the master switch, IP allowlist, entity-type allow/deny policy, and the write gate, matching the existing-entity semantics. |
| **JSON:API request seam** (`McpJsonApiPageLimitSubscriber`) | Enforces the IP allowlist for **all** governed JSON:API traffic — collection (`/jsonapi/node/article`), individual, and writes — so collection enumeration from a disallowed IP is denied (403), not only individual `/{uuid}` reads. Also enforces `result_count_cap` on `page[limit]`. |
| **`McpContentLockTool`** | `checkAccess()` — IP-denied governed accounts receive a forbidden `AccessResult` before any lock state is read or mutated. |
| **`McpSecurityPolicyTool`** | `checkAccess()` — IP-denied governed accounts cannot read the policy profile data. |
| **`McpSiteContextTool`** | `checkAccess()` — IP-denied governed accounts cannot read the site schema. |
| **`/drupal-mcp/context` endpoint** | `McpContextController::context()` — returns 403 with a `no-store` response header before any schema data is serialized. |

A denied request returns a "Source IP not permitted by MCP Sentinel policy."
message. CIDR matching (including IPv6) is performed by
`Symfony\Component\HttpFoundation\IpUtils::checkIp()`, which is bundled with
Drupal core.

**Cache safety:** when a profile has a non-empty `allowed_ips` list, every
`AccessResult` returned by `checkEntityAccess()` is marked `max-age 0`
(uncacheable). Client IP is not a Drupal cache context, so a cached "allowed"
result would be re-served to a later request from the same account but a
different, disallowed IP — bypassing the gate. The `no-store` header on
`McpContextController` responses provides the same protection for the HTTP layer.

The gate is applied **only to governed requests** (requests where a policy
profile resolves for the account). Ungoverned cookie-session traffic is never
affected.

### IMPORTANT — Reverse-proxy / trusted-proxy requirement

The client IP is read via **Symfony's trusted-proxy-aware `Request::getClientIp()`**,
which honors `X-Forwarded-For` *only* when the connecting proxy's own IP is
listed in Drupal's trusted-proxy configuration. If your site sits behind a load
balancer or CDN you **MUST** configure the following in `settings.php`:

```php
$settings['reverse_proxy'] = TRUE;
$settings['reverse_proxy_addresses'] = ['10.0.0.0/8', '172.16.0.0/12'];
// Use the real proxy/LB address ranges for your environment.
```

**Without these settings** every request appears to originate from the proxy's
IP regardless of the real client, which means:

- **Lockout risk:** a correct allowlist will deny all agents because their real
  IPs are never seen.
- **Bypass risk:** if you add the proxy IP to the allowlist to work around the
  above, all agents pass the check regardless of their actual source IP.

The empty-list default (`allowed_ips: []`) disables IP enforcement entirely and
is always safe to leave in place if you are not ready to configure trusted
proxies.

### Spoofing protection

An attacker cannot bypass the allowlist by forging an `X-Forwarded-For` header.
Symfony only trusts that header when the *socket-level* connecting IP (`REMOTE_ADDR`)
matches a configured trusted proxy. A request arriving from an untrusted IP is
evaluated against `REMOTE_ADDR` directly — the forged header is ignored.

## Anomaly detection & alerting

MCP Sentinel can evaluate threshold rules over the audit log on each cron run
and fire alerts when a rule trips. This lets you detect bulk-delete spikes,
access-denial storms, and other unusual agent behaviour automatically.

### How rules work

Each rule specifies:

| Field | Description |
|---|---|
| `id` | Unique machine name (lowercase letters, numbers, underscores). |
| `label` | Human-readable name shown in alerts. |
| `operation_pattern` | Match against the audit log `operation` column. **Exact match by default** — `entity_delete` matches only `entity_delete`. Append `*` for prefix matching — `entity*` matches `entity_save`, `entity_delete`, etc. The `denied_access` operation is written by governed Tool plugins when an agent is denied by policy or core access. |
| `window_seconds` | Look-back window. Only rows newer than `now - window_seconds` are counted. |
| `threshold` | Minimum row count to trigger the rule. |
| `debounce_seconds` | Minimum seconds between alerts for this rule (default 3600). Prevents alert storms. |
| `enabled` | `1` to enable; `0` to disable. |

Rules are evaluated on cron. All rules ship **disabled by default** to avoid
false positives during content imports. Enable and tune rules per-site.

### Alert channels

Three channels are available — mix and match:

| Channel | Setting | Behaviour |
|---|---|---|
| **Log** | `anomaly_alert_log` (default `true`) | Writes a `warning` to the `mcp_sentinel` logger channel. Route this channel to syslog/SIEM for monitoring. |
| **Email** | `anomaly_alert_email` | Sends an email to the configured address when non-empty; empty = disabled. Requires a working mail setup. |
| **Webhook** | `anomaly_alert_webhook` | Enqueues an `mcp.anomaly.alert` event through the reliable webhook queue manager. Endpoints whose event filter includes `mcp.anomaly.alert` (or an empty filter) receive it, with retry/backoff/HMAC inherited. |

### Enabling anomaly detection

1. Go to **Configuration → Web services → MCP Sentinel**.
2. In the *Anomaly detection* tab, check **Enable anomaly detection**.
3. Configure alert channels (log is on by default; add an email and/or enable
   webhook delivery as needed).
4. Add rules with the **Rules** editor. Each rule is its own row with separate
   **Machine ID**, **Label**, **Operation pattern**, **Window (s)**,
   **Threshold**, **Debounce (s)**, and **Enabled** fields; use **Add rule** /
   **Remove rule N** to manage rows. For example, add three rules:

   | Machine ID | Label | Operation pattern | Window (s) | Threshold | Debounce (s) | Enabled |
   |------------|-------|-------------------|------------|-----------|--------------|---------|
   | `denied_access_storm` | Denied access storm | `denied_access` | 300 | 20 | 3600 | ✓ |
   | `bulk_delete` | Bulk delete spike | `entity_delete` | 300 | 20 | 3600 | ✓ |
   | `entity_activity` | Entity write spike | `entity*` | 300 | 100 | 3600 | |

   The first rule uses an exact pattern (`denied_access`) and fires when a
   governed agent is denied 20+ times in 5 minutes. The third rule uses the
   `*` prefix to match all `entity_*` operations.
5. Save. Alerts will fire on the next cron run where a rule is tripped.

### Debounce (alert-storm suppression)

The `debounce_seconds` field prevents a misconfigured rule from alerting on
every cron run. After a rule fires, it is suppressed for `debounce_seconds`
using `@state` (key `mcp_sentinel.anomaly_last_alert.{rule_id}`). Set
`debounce_seconds` to `0` only for rules where you need unrestricted frequency.

### Performance notes

Queries hit only the indexed `operation` and `timestamp` columns of
`mcp_sentinel_audit_log` — no full-table scans. Each rule is one
lightweight `COUNT` query. A bad rule (zero threshold, empty pattern) is
skipped with a log warning rather than fataling cron.

## Reliable webhooks

MCP change events (`mcp.entity.presave`, `mcp.entity.delete`) are delivered to
external HTTPS endpoints through the Drupal queue system — not fire-and-forget —
so a notification is never lost if the request ends before the HTTP call
settles. Each delivery is signed, retried with backoff, recorded in a delivery
log, and replayable.

### Endpoints

Configure one or more endpoints in the *Reliable webhooks* tab of the settings
form. Each endpoint is its own add/remove row (use **Add endpoint** /
**Remove endpoint N**) with these fields:

| Field | Purpose |
|-------|---------|
| **Machine ID** | Stable identifier used in the delivery log. |
| **Label** | Human-readable name. |
| **URL** | HTTPS endpoint (plain HTTP is rejected). |
| **Signing secret** | A [Key](https://www.drupal.org/project/key) entity holding the HMAC secret. Use a File or Environment key provider so the value never lands in exported config. |
| **Event filter** | One event name per line; leave empty to receive all events. |
| **Enabled** | Toggles delivery without deleting the endpoint. |

The request body is signed with HMAC-SHA256 and sent in the
`X-MCP-Signature: sha256=…` header. Verify it with:

```
hash_equals('sha256=' . hash_hmac('sha256', $body, $secret), $header)
```

### Retry behavior

Delivery runs in the `mcp_sentinel_webhook_delivery` QueueWorker (processed on
cron). A non-2xx response or network error schedules a retry: **5 attempts**
with backoff intervals of **30 s, 5 min, 30 min, 2 h, 8 h**. After the final
attempt the delivery is marked `failed`. A row already `sent` is never
re-delivered, so duplicate queue items or concurrent workers cannot double-send.

### Delivery log + replay

`/admin/reports/mcp-sentinel/webhooks` (permission *Administer MCP Sentinel
settings*) lists recent deliveries with status, attempts, last response code, and next
attempt time. Use the CSRF-protected **Replay** action — or
`drush mcp-sentinel:webhook-replay <delivery-id>` — to reset a `failed`/`sent`
row to `pending` and re-queue it.

### SSRF protection (HTTPS required)

All endpoints must use `https://`. A two-layer SSRF guard runs at enqueue time
and again at send time (DNS can rebind in between): the worker resolves the
host and blocks any address in a private, loopback, link-local, or reserved
range (RFC1918 `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `127/8`, `::1`,
`fc00::/7`, …); such deliveries are marked `failed_ssrf`. For a legitimate
internal-network or VPN target, check that endpoint's **Allow internal/private
IP** toggle — this disables the resolved-IP check for that endpoint only; HTTPS
is still enforced. (The legacy global `allow_internal_webhook_urls` setting is
deprecated in favour of the per-endpoint toggle.)

### Retention / prune

The delivery log is bounded by `webhook_delivery_retention_days` (default 30,
`0` = forever). Rows past the window are deleted on cron and by
`drush mcp-sentinel:webhook-prune`.

### Migrating from the legacy single webhook

Sites that used the old single `webhook_url`/`webhook_secret_key` settings are
migrated automatically (`update_10008`) into one `webhook_endpoints` entry. The
legacy fields remain visible in the form with a deprecation notice for review;
clear them once the migrated endpoint is verified.

## Configuration

The module adds two admin-menu entries, so both landing pages are reachable
without knowing their URLs:

- **Configuration → Web services → MCP Sentinel** — the settings form.
- **Reports → MCP Sentinel** — the governance dashboard.

(Policy profiles remain at **Configuration → Web services → MCP policy
profiles**.) The settings form also opens with a collapsed **Setup &
configuration guide** — a short site-builder quickstart that links out to this
README, `INSTALL.md`, and the in-site Keys and policy-profile pages.

Admin routes:

- `/admin/config/services/mcp-sentinel` — settings form (master switch,
  governance model, audit, encryption, DLP, rate limits, anomaly rules, IP
  allowlists, webhook endpoints). Linked from **Configuration → Web services**.
- `/admin/reports/mcp-sentinel` — **governance dashboard** (landing page; see
  below), linked from the **Reports** menu. Local-task tabs lead to the audit
  log, webhook deliveries, and (when the approval submodule is enabled)
  approvals.
- `/admin/reports/mcp-sentinel/audit` — audit log listing, with filters and
  CSV/JSON export.
- `/admin/reports/mcp-sentinel/webhooks` — webhook delivery log + replay.
- `/admin/help/mcp_sentinel` — module help overview (requires the core Help
  module).

### Governance dashboard

`/admin/reports/mcp-sentinel` is a read-only operations console (permission
*View MCP Sentinel audit log*) built entirely from data the module already
stores — it performs no writes and re-verifies nothing on load. It surfaces:

- an **urgent-conditions banner** (broken hash chain, unresolvable encryption
  profile or webhook signing key, governance switched off while traffic flows,
  and the operator broadcast message);
- a **posture hero** rolling up how many items need attention (urgent
  conditions + pending approvals + anomaly alerts + webhook failures), or an
  all-clear state;
- **five status tiles** — Governance, Audit, Anomaly, Approvals, Webhooks —
  each linking into the relevant report;
- a **chain-integrity card** reflecting the last stored verify result;
- **top-agents** and **denied-by-policy** panels;
- a **quick-actions** bar (including **Verify chain now**, a CSRF-protected
  action that re-runs the hash-chain check, records the result, and returns to
  the dashboard with a status message) and an **active-controls** strip showing
  which controls (hash chain, encryption, SIEM, DLP, rate limiting, IP
  allowlist, approvals) are on;
- **six charts** — audit volume over time (anomaly buckets flagged),
  allowed-vs-denied, operation mix, top agents, denied reasons, and webhook
  health.

A **time-window toggle** (`?window=24h|7d|30d`, default 24h, validated) re-scopes
every count and chart via plain server-rendered links — no heavy JavaScript.
Charts and tiles **click through** to the audit log filtered to the relevant
slice (e.g. the volume chart and the Audit tile link to
`/admin/reports/mcp-sentinel/audit`; the denied-reasons chart links to
`?operation=denied_access`).

Charts render as self-contained inline SVG by default; installing the optional
`drupal/charts` contrib module (a composer `suggest`) upgrades them to
interactive charts with no code change. Every widget is built behind its own
guard, so a single failing metric degrades to an empty/"—" widget rather than
breaking the page. The dashboard renders even when the approval submodule is
absent and when `drupal/charts` is not installed.

**Critical** urgent conditions (a broken hash chain, an unresolvable encryption
profile, or an unresolvable webhook signing key) also appear as a dismissible
banner on every admin page — not just the dashboard — for users with *View MCP
Sentinel audit log*, so they are noticed promptly. Warning/info conditions are
shown on the dashboard only. Dismissal is per-user and the banner reappears
while the condition still holds.

## Escape-hatch permission assertions

A policy profile constrains the **MCP channel**. The governed Drupal **role** is
a separate boundary, and some permissions walk straight around the first one:

- `bypass file gate` — File Gate declines its veto for any account holding it,
  so gated private files are fetchable at `/system/files/…` directly.
- `bypass node access`, `administer users`, `administer permissions`,
  `masquerade as any user`, `administer site configuration` — each reads or
  writes outside the agent channel, where no policy, redaction or audit applies.

A role holding one of these does not make the profile *weaker*; it makes the
profile's guarantees **untrue**. So each profile asserts them:

```yaml
forbidden_role_permissions:
  - 'bypass file gate'
  - 'bypass node access'
  - 'administer users'
  - 'administer permissions'
  - 'masquerade as any user'
  - 'administer site configuration'
acknowledged_role_permissions: []   # 'role_id:permission' or 'role_id:permission@environment'
```

The list ships populated, so the protection is inherited without authoring it,
and it is per-profile configuration — add the escape hatches your own contrib
modules define.

**Effective permissions, not listed ones.** Every governed account is
authenticated, so a bypass granted to the `authenticated` role is held by every
governed role while appearing in none of their permission arrays. The check
resolves both, and says which it found — the fix differs (revoke it from the
agent role, or from every logged-in user).

**Admin roles are refused, not scanned.** An `is_admin` role holds every
permission implicitly, including ones a module installed tomorrow will define,
so no list can enumerate it and no profile can constrain it. The settings form
and the profile form **reject** an admin role outright. An admin role already
configured is still governed at runtime and reported loudly — un-governing it
would leave the agent's traffic ungoverned entirely, which is worse.

**Where violations appear:**

| Surface | Behaviour |
|---------|-----------|
| Governance dashboard | Critical banner condition, counted in "needs attention" |
| **Reports → Status report** | `MCP Sentinel: governed role holds an escape-hatch permission`, at ERROR |
| `drush mcp-sentinel:role-audit` | Non-zero exit — the deploy-time gate |
| On role save | Logged at error and written to the audit chain as `role_escape_hatch` |

The role-save check records; it does not block. Refusing the save would break
config import and put this module in the way of an operator changing their own
site's permissions. Run `drush mcp-sentinel:role-audit` after `config:import` in
your deploy — by then every role and profile is in its final state.

**Recording a deliberate exception.** Add `role_id:permission` to
`acknowledged_role_permissions` rather than deleting the rule that caught it —
the acknowledgement is exported configuration, so the decision is visible in
review and in the config diff, and every *other* forbidden permission stays
asserted for that role.

**Environment-scoped exceptions.** Some grants are legitimate on one environment
and a violation on another — for example a config-editor role that needs
`administer site configuration` on dev (where config is authored) but must not
have it on prod. Scope the acknowledgement:

```yaml
acknowledged_role_permissions:
  - 'mcp_config_editor:administer site configuration@dev'
```

The environment name comes from **settings.php**, never from config:

```php
// settings.php (per environment; not exported)
$settings['mcp_sentinel.environment'] = 'dev';
```

Unscoped entries keep working on every environment. With no environment
declared, a scoped entry does **not** apply — the violation is reported. A site
that forgets to set it gets the strict answer, never the permissive one. The
module ships the mechanism; environment *names* belong to the site.

An `is_admin` role cannot be acknowledged into compliance: it holds every
permission implicitly, so no list can enumerate it.

## Raw SQL (opt-in, governed, and recorded)

Raw SQL runs underneath the entity API. Nothing that makes `denied_entity_types`
or `redacted_fields` mean anything is on its path, so a statement reading a
field table directly returns data the same profile would refuse through JSON:API
or a Tool plugin. Adding entity types to a deny list does not change that — the
boundary is in the wrong place.

`drush mcp-sentinel:sql-query` is the governed replacement. It is a
module-provided command, so Drupal is fully bootstrapped when it runs and the
policy profile, the statement guard and the audit chain all apply:

```bash
# Refused: the shipped profile does not allow raw SQL.
drush mcp-sentinel:sql-query 'SELECT nid, title FROM node_field_data'

# After enabling allow_raw_sql on the profile:
drush mcp-sentinel:sql-query 'SELECT nid, title FROM node_field_data'
drush mcp-sentinel:sql-query --profile=auditor 'SELECT COUNT(*) FROM node_field_data'
```

**The capability ships off.** `allow_raw_sql` is `FALSE` on the default profile
and on every profile upgraded from an earlier release. Turning it on is an
exported configuration change — a decision somebody made and a reviewer can see.

**What the guard permits**, checked against the *same* profile that governs the
entity API:

- a single `SELECT` — no stacked statements, no comments, no `INTO`
- only tables belonging to an entity type the profile allows. Every other table
  is refused, core's included: the `config` table alone carries every
  configuration object (Key provider values among them), and it is not an
  entity table, so no entity-type deny list would ever have covered it
- no reference to a column backing a redacted field — anywhere, not only in the
  select list. `WHERE mail LIKE 'a%'` never returns the value but recovers it a
  character at a time
- select lists limited to columns, `table.column`, `*`, and `COUNT()`. Arbitrary
  expressions are refused because `SUBSTR(mail, 1, 3)` defeats output masking
- `SELECT *` refused on any table carrying a redacted column
- the profile's `result_count_cap` applies, as it does to any other response

**Every invocation is written to the audit chain with the statement text** —
refusals as `raw_sql_denied`, permitted statements as `raw_sql_query` — whether
or not read logging is enabled. If audit logging is off, the command refuses to
run at all: a capability justified by being recorded is not run unrecorded.

**What this costs.** The tool is far narrower than `drush sql:query`: no joins
onto denied types, no expressions, no aggregates beyond `COUNT()`, no `SELECT *`
on a table holding a redacted column. Existing operator queries will need
rewriting or belong on the operator's own shell. And the guard is deliberately
not a SQL parser — a parser would invite the belief that raw SQL is *fully*
governed, and it is not: an expression over an allowed column can still say more
than an entity read would. That residual risk is why the capability is off by
default rather than merely guarded.

### Drush commands

| Command | Purpose |
|---------|---------|
| `drush mcp-sentinel:status` | Print source-contract readiness, active policy, audit, and lock state. Exits non-zero whenever the connector-facing source contract is not ready. |
| `drush mcp-sentinel:role-audit` | Fail (non-zero) if a governed role holds a permission its profile forbids. Deploy gate. |
| `drush mcp-sentinel:sql-query <sql> [--profile=ID]` | Run a single read-only SELECT under a policy profile. Refused unless the profile sets `allow_raw_sql`; every attempt is audited. |
| `drush mcp-sentinel:audit-verify` | Verify the tamper-evident audit-log hash chain. |
| `drush mcp-sentinel:audit-purge` | Delete audit entries past the retention window (also runs on cron). |
| `drush mcp-sentinel:lock-clear` | Release expired content locks (also runs on cron). |
| `drush mcp-sentinel:webhook-prune` | Delete webhook delivery rows past retention (also runs on cron). |
| `drush mcp-sentinel:webhook-replay <id>` | Reset a delivery row to pending and re-queue it. |
| `drush mcp-sentinel:setup [--allow-unauthenticated-development]` | (submodule) Preflight and register Sentinel Tool plugins with required OAuth by default. The development escape is explicitly not ready and exits non-zero. |
| `drush mcp-sentinel:teardown` | (submodule) Unregister all Sentinel tools from mcp_server. |
| `drush mcp-sentinel:agent-provision <tier> --env=<env>` | (submodule) Provision an agent tier — `content`, `content-auditor`, `auditor`, `developer`, or `admin` — as a role + service account + OAuth consumer (`<tier>-<env>`). Never creates or rotates secrets. |
| `drush mcp-sentinel:break-glass <uid>` | (approval submodule) Request the time-boxed `mcp_admin` break-glass role for a user; always approval-gated, auto-revoked at the configured TTL. |

## Companion Node.js Connector

[drupal-mcp-connector](https://github.com/Wilkes-Liberty/drupal-mcp-connector) is a
separate, optional Node.js MCP connector — not part of this module and not a
count of Sentinel's own plugins. It exposes **66 connector tools across 9
modules** (multi-site, GraphQL, and a Drush bridge) that an MCP client can call
against a Drupal site. MCP Sentinel governs those calls when they reach Drupal;
it does not provide them. For reference, this module itself ships 10 base Tool
plugins plus 1 conditional GraphQL schema tool (via `mcp_sentinel_graphql`).

MCP Sentinel implements **Integration Contract v1.0** (published by the connector
at `docs/integration-contract.md` in
[Wilkes-Liberty/drupal-mcp-connector](https://github.com/Wilkes-Liberty/drupal-mcp-connector)):
log-only `X-MCP-Client` identity, the `mcp_read` / `mcp_write` OAuth scopes, the
`/drupal-mcp/context` endpoint, and server-authoritative authorization keyed on
role + scopes. Compatibility: mcp_sentinel ≥ 1.0 ↔ drupal-mcp-connector ≥ 0.6
(contract 1.0). See [`docs/CONNECTOR.md`](docs/CONNECTOR.md).

## Maintainers

- Jeremy Michael Cerda — <jmcerda@wilkesliberty.com>
- Wilkes & Liberty, LLC — [drupal.org/u/wilkes-liberty](https://www.drupal.org/u/wilkes-liberty)

See `MAINTAINERS.txt`. Report issues and feature requests in the
[project issue queue](https://www.drupal.org/project/issues/mcp_sentinel); report
sensitive security issues to the Drupal security team at security@drupal.org.
