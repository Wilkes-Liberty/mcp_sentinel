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
| Tamper-evident audit hash chain | ❌ | ✅ |
| Content locks | ❌ | ✅ |
| HMAC webhooks | ❌ | ✅ |
| Rich context endpoint | ❌ | ✅ |
| mcp_api role | ❌ | ✅ |

## Tamper-evident audit log

Every audit row stores a `prev_hash` and a `row_hash` (SHA-256 of the prior
row's hash concatenated with a canonical JSON of this row's content). Inserting,
deleting, or editing any historical row breaks the cryptographic chain.

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

Custom patterns are stored in the `dlp_patterns` config sequence. Each entry
has three keys:

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
