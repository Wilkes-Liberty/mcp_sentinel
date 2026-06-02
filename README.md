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

## Requirements

- Drupal 10.3+ or 11
- [Tool API](https://www.drupal.org/project/tool) (`drupal/tool`)
- [Key](https://www.drupal.org/project/key) (`drupal/key`) — stores the webhook
  signing secret and (optionally) the audit encryption key outside exported
  configuration
- [Encrypt](https://www.drupal.org/project/encrypt) (`drupal/encrypt`) —
  provides Encryption Profiles for optional at-rest encryption of audit metadata
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
| Field-level PII redaction | ❌ | ✅ |
| DLP value-pattern redaction / masking | ❌ | ✅ |
| Audit log | ❌ | ✅ |
| Filterable audit UI + CSV/JSON export | ❌ | ✅ |
| Redaction-aware change diffs | ❌ | ✅ |
| Tamper-evident audit hash chain | ❌ | ✅ |
| At-rest audit metadata encryption | ❌ | ✅ |
| SIEM streaming | ❌ | ✅ |
| Content locks | ❌ | ✅ |
| HMAC webhooks | ❌ | ✅ |
| Human approval workflow (submodule) | ❌ | ✅ |
| Rich context endpoint | ❌ | ✅ |
| mcp_api role | ❌ | ✅ |

## Tamper-evident audit log

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
   MCP Sentinel**), open the *Audit Logging* fieldset and choose your
   Encryption Profile from the *Audit metadata encryption profile* select.
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
   *Data Loss Prevention (DLP)* fieldset.
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

Operators can configure custom patterns directly from the settings form:

1. Go to **Configuration → Web services → MCP Sentinel**.
2. Enable DLP and open the *Custom DLP patterns* textarea.
3. Enter one pattern per line in the format `label|regex|mask` (`mask` is
   optional and defaults to `*`). Example:

   ```
   employee_id|EMP-\d{6}|*
   internal_ref|CUST-\d{8}
   ```

4. Save. Invalid regex lines are rejected with a validation error before saving.

Leaving the textarea empty clears any custom patterns and falls back to the
four built-in defaults (email, US phone, SSN, credit card) at runtime.

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
2. In the *Rate limits* fieldset:
   - **Max requests per window** — maximum governed tool calls allowed in the
     window. `0` means unlimited (the default on all shipped profiles).
   - **Window (seconds)** — the rolling window duration. Default is `60`.
3. Save. The limit takes effect immediately for new requests.

### Recommended starting point for production

`300` requests per `60` second window is a reasonable baseline for most sites.
Adjust based on observed agent traffic patterns.

### How it works

- The flood key is `mcp_sentinel.profile.{profile_id}.{uid}` where `{uid}` is
  the server-resolved authenticated user ID — never an agent-supplied value.
  This prevents key-cycling bypass attacks.
- A limit of `0` short-circuits before touching the flood service, so an
  unconfigured profile never incurs unnecessary flood writes.
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
2. In the *Exfiltration guards* fieldset:
   - **Max result items** — maximum items returned per Tool call, JSON:API page
     request, or GraphQL multi-value field result list. `0` means unlimited (the
     default on all shipped profiles). Recommended: `500`.
   - **Max response size in bytes** — maximum serialized response size for
     governed Tool calls. Responses exceeding this limit are denied. `0` means
     unlimited. Recommended: `2097152` (2 MB).
3. Save. Limits take effect immediately.

### Enforcement seams

| Seam | How caps are applied |
|------|----------------------|
| **Tool output** | `McpBulkOperationsTool` truncates `succeeded` list to `result_count_cap`; adds `_result_truncated: true` + `_result_cap` to the result data. Response-size cap is measured on the serialized payload. |
| **JSON:API** | A `KernelEvents::REQUEST` subscriber blocks `page[limit]` values above `result_count_cap` for governed requests with HTTP 400 before the DB query runs. (`hook_jsonapi_resource_params_alter` does not exist in Drupal 11.3; the subscriber is the correct implementation.) |
| **GraphQL** | `hook_graphql_compose_field_results_alter` in `mcp_sentinel_graphql` truncates multi-value field result lists to `result_count_cap` as a third pass after redaction and DLP masking. |

Ungoverned requests and profiles with `result_count_cap = 0` are never capped.
The response-size cap applies to Tool output only (JSON:API and GraphQL
response-size enforcement is deferred to a future pass).

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
