# MCP Sentinel — Connector ↔ Drupal Contract & Per-Environment Runbook

> **Audience:** DevOps / platform engineers wiring the `drupal-mcp-connector`
> connector to a Drupal site protected by MCP Sentinel. This document covers
> the authorization model, per-environment configuration steps, and the
> end-to-end manual verification procedure.

---

## Integration Contract v1.0

MCP Sentinel implements **Integration Contract v1.0**, the shared contract
published by the companion connector at `docs/integration-contract.md` in
[Wilkes-Liberty/drupal-mcp-connector](https://github.com/Wilkes-Liberty/drupal-mcp-connector).
On the Drupal side that means:

- **Log-only `X-MCP-Client` identity.** The connector's self-reported client
  label is recorded in the audit log (as the `mcp_client` metadata field) for
  forensics only — it is never an enforcement signal.
- **OAuth scopes `mcp_read` / `mcp_write` / `mcp_config`.** Read/explain tools
  require `mcp_read`; content write tools require `mcp_write`; the configuration
  tools (`config_get` / `config_list` / `config_set`) require the dedicated
  `mcp_config` scope so config management is isolated to the dev/config tier and
  a content-tier token can never reach it.
- **The `/drupal-mcp/context` endpoint** exposes the governed site schema.
- **Server-authoritative authorization keyed on role + scopes.** Every gate is
  decided server-side from the authenticated role and the token's OAuth scopes —
  never from a client-supplied header.

**Compatibility:** mcp_sentinel ≥ 1.0 ↔ drupal-mcp-connector ≥ 0.6 (contract 1.0).

---

## 1. Authorization model

### Grant type

The preferred grant for **per-admin attribution** is
**`authorization_code` + PKCE**, federated to the existing IdP (Keycloak,
already wired as `openid_connect.client.sign_in_with_keycloak` on this site).
The flow is:

```
Agent / MCP client
    │  authorization_code + PKCE  (browser or device-flow redirect)
    ▼
Keycloak (IdP)
    │  id_token / authorization code
    ▼
Drupal simple_oauth  (token endpoint: /oauth/token)
    │  access_token (≤ 3600 s) + refresh_token
    ▼
drupal-mcp-connector connector
    │  Authorization: Bearer <access_token>
    ▼
Drupal JSON:API / Tool API  →  MCP Sentinel governance
```

For **unattended / service-account** agent jobs, `client_credentials` may be
used instead; attribution will appear as the Consumer's machine account rather
than a named admin.

### Token endpoint

```
POST <INTERNAL_BASE_URL>/oauth/token
```

Replace `<INTERNAL_BASE_URL>` with the environment-specific internal hostname
(§3). The token endpoint must **not** be exposed on the public-facing hostname.

### Access-token TTL

`simple_oauth.settings` must be configured with:

- `access_token_expiration` ≤ `3600` seconds (1 hour).
- Refresh tokens enabled (`use_refresh_tokens: true`, TTL ≥ 7 days; this site
  uses `refresh_token_expiration: 1209600` = 14 days).

### Connector refresh behavior

The connector **auto-refreshes silently** on access-token expiry using the
refresh token — it does **not** surface a `401` for routine 1-hour expiry. A
`401` is surfaced (and an operator must reissue / re-authorize) **only** when
the refresh token itself is expired or revoked. Rationale: with unattended
agent jobs and a 1-hour access token, surfacing a 401 on every expiry would
make the connector brittle; the 14-day refresh token absorbs routine rotation,
so a hard 401 then unambiguously means the credential genuinely needs
re-issuing.

---

## 2. Per-tool scope enforcement

Each `mcp_tool_config` entity carries third-party settings under the
`mcp_server_oauth` namespace (written by
`drush mcp-sentinel:setup`):

| Setting | Value |
|---------|-------|
| `authentication_mode` | `required` |
| `scopes` | `mcp_read` (read/explain tools), `mcp_write` (content write tools), or `mcp_config` (config tools) |

The `mcp_server_oauth` subscriber enforces these per tool call — a token that
lacks the required scope is rejected before governance even fires.

> **Production requires `mcp_server_oauth`.** The base module's non-Tool Drupal
> controls can exist without MCP Server, but the connector-facing product
> contract cannot be ready without per-Tool OAuth enforcement. The default
> setup path refuses to run when the OAuth submodule is absent; the explicit
> unauthenticated development escape remains not ready and exits non-zero.

### Tool → scope mapping

| Tool | Scope |
|------|-------|
| `mcp_sentinel_site_context` | `mcp_read` |
| `mcp_sentinel_security_policy` | `mcp_read` |
| `mcp_sentinel_graphql_schema` | `mcp_read` |
| `mcp_sentinel_content_lock` | `mcp_write` |
| `mcp_sentinel_node_operations` | `mcp_write` |
| `mcp_sentinel_media_create` | `mcp_write` |
| `mcp_sentinel_workflow_transition` | `mcp_write` |
| `mcp_sentinel_bulk_operations` | `mcp_write` |
| `mcp_sentinel_config_get` | `mcp_config_read` |
| `mcp_sentinel_config_list` | `mcp_config_read` |
| `mcp_sentinel_config_set` | `mcp_config` |

> **Config tools are config-tier only.** The read tools require
> `mcp_config_read`; the write tool requires `mcp_config`, never `mcp_write`.
> A content-tier token (`mcp_read` +
> `mcp_write`) is therefore denied on every config tool at the transport layer,
> before governance fires. Grant `mcp_config` only to the dev/config consumer
> (the `developer` / `admin` tiers in `mcp-sentinel:agent-provision`).

---

## 3. Per-environment setup

Repeat the steps in this section for **each** environment
(local / staging / prod). Do not share Consumer clients across environments.

### Environment variables (operator to fill)

| Variable | Description |
|----------|-------------|
| `INTERNAL_BASE_URL` | Internal-VPN-only hostname, e.g. `https://PLACEHOLDER-staging.internal` |
| `CLIENT_ID` | Consumer `client_id` chosen during step 3.2 |
| `CLIENT_SECRET` | Consumer client secret (store in a Key entity or vault) |

> **Keep hostnames out of version control.** Real per-environment
> `INTERNAL_BASE_URL` values are intentionally NOT recorded in this published
> runbook. Supply them through environment variables, local (uncommitted)
> settings, or a secrets manager. The `PLACEHOLDER-*.internal` strings here are
> deliberate — do not replace them with real hostnames in a committed file.

> **Security note:** The JSON:API write plane and the `/oauth/token` endpoint
> must be exposed **only** on an internal VPN hostname, never on the
> public-facing URL. Enforce this at the reverse proxy / load balancer.

### 3.1 Scope entities

Create four simple_oauth scope entities (or use `simple_oauth_static_scope` for
static scope definitions). `mcp_config_read` is read-only config access;
`mcp_config` is config write. Ship them only where an auditor/dev consumer
needs them:

```bash
# mcp_read
ddev drush php:eval "
  \$scope = \Drupal\simple_oauth\Entity\Oauth2Scope::create([
    'id' => 'mcp_read',
    'name' => 'mcp_read',
    'description' => 'MCP read/explain tools',
    'grant_types' => [
      'authorization_code' => ['status' => TRUE],
      'client_credentials' => ['status' => TRUE],
    ],
    'umbrella' => FALSE,
  ]);
  \$scope->save();
"

# mcp_write
ddev drush php:eval "
  \$scope = \Drupal\simple_oauth\Entity\Oauth2Scope::create([
    'id' => 'mcp_write',
    'name' => 'mcp_write',
    'description' => 'MCP write tools',
    'grant_types' => [
      'authorization_code' => ['status' => TRUE],
      'client_credentials' => ['status' => TRUE],
    ],
    'umbrella' => FALSE,
  ]);
  \$scope->save();
"

# mcp_config_read (config_get / config_list)
ddev drush php:eval "
  \$scope = \Drupal\simple_oauth\Entity\Oauth2Scope::create([
    'id' => 'mcp_config_read',
    'name' => 'mcp_config_read',
    'description' => 'MCP config read tools — auditor/dev tier only',
    'grant_types' => [
      'authorization_code' => ['status' => TRUE],
      'client_credentials' => ['status' => TRUE],
    ],
    'umbrella' => FALSE,
  ]);
  \$scope->save();
"

# mcp_config (config_set only)
ddev drush php:eval "
  \$scope = \Drupal\simple_oauth\Entity\Oauth2Scope::create([
    'id' => 'mcp_config',
    'name' => 'mcp_config',
    'description' => 'MCP config (site-building) tools — dev/config tier only',
    'grant_types' => [
      'authorization_code' => ['status' => TRUE],
      'client_credentials' => ['status' => TRUE],
    ],
    'umbrella' => FALSE,
  ]);
  \$scope->save();
"
```

> **Scope `name` must equal the machine `id`.** MCP Sentinel governance matches
> the scope *name* carried on the validated token against
> `mcp_sentinel.settings:agent_scopes`. These ship as `mcp_read` / `mcp_write` /
> `mcp_config_read` / `mcp_config` (underscore). If a scope `name` differs from the configured
> `agent_scopes`, governance will never recognise the token as the agent channel
> and the governed product path is refused. See UPGRADE.md if you previously
> created colon-form (`mcp:read` / `mcp:write`) scopes.

### 3.2 Designated Consumer and bound account (one per environment)

First create an enabled policy profile whose `roles` include the selected
tier's role (see §3.5; the `content` tier uses `mcp_content_editor`). Then use
the provisioning command so Consumer, active owner account, role, scopes, and
designation are written as one rollback-safe batch:

```bash
ddev drush mcp-sentinel:agent-provision content --env=staging
```

The deterministic `client_id` is `content-staging`. The command never creates,
prints, changes, or rotates a secret; set it out of band through the Consumer
UI/Key provider after provisioning. A missing scope, blocked owner, or absent
applicable profile fails before designation; a later write failure rolls the
entire identity batch back.

### 3.3 MCP Sentinel agent-channel settings

`agent-provision` writes the exact Consumer client ID into Sentinel settings as
its final step. Verify that designation rather than maintaining it separately:

```bash
ddev drush php:eval "
  \Drupal::configFactory()
    ->getEditable('mcp_sentinel.settings')
    ->get('agent_oauth_clients');
"
```

> **Important:** an empty `agent_oauth_clients` value is not production-ready.
> Scope-only recognition remains useful for legacy/non-product integrations,
> but every governed Tool/context/connector path requires an exact designated,
> enabled Consumer bound to an active account and applicable role-bound profile.

### 3.4 simple_oauth token TTL

```bash
ddev drush php:eval "
  \Drupal::configFactory()
    ->getEditable('simple_oauth.settings')
    ->set('access_token_expiration', 3600)
    ->set('use_refresh_tokens', TRUE)
    ->set('refresh_token_expiration', 1209600)
    ->save();
"
```

### 3.5 Agent policy profile

Create (or update) the `mcp_policy_profile` entity for the admin role bound to
the agent plane. The recommended **production** profile:

```bash
ddev drush php:eval "
  \$p = \Drupal\mcp_sentinel\Entity\McpPolicyProfile::load('agent_prod');
  if (!\$p) {
    \$p = \Drupal\mcp_sentinel\Entity\McpPolicyProfile::create(['id' => 'agent_prod']);
  }
  \$p->set('label', 'Agent (production)')
    ->set('roles', ['mcp_content_editor']) // content tier role
    ->set('weight', 10)
    ->set('allow_read', TRUE)
    ->set('allow_write', TRUE)
    ->set('allow_delete', FALSE)          // NEVER delete on prod via agent
    ->set('allow_graphql_mutations', FALSE)
    ->set('allowed_entity_types', ['node', 'taxonomy_term', 'media'])
    ->set('denied_entity_types', ['user'])
    ->set('redacted_fields', ['pass', 'mail'])
    ->save();
  echo 'Profile saved.' . PHP_EOL;
"
```

**Key production constraints:**
- `allow_delete: false` — agents must never delete content on production.
  Deletions are performed by humans via the standard Drupal admin UI.
  - **Scoped exception (per-entity-type override).** When a single low-risk type
    needs agent-driven cleanup (e.g. de-duping `taxonomy_term`), grant delete for
    that type only via the `entity_rules` map instead of flipping the global
    flag:

    ```php
    $p->set('allow_delete', FALSE)                  // global default: no delete
      ->set('entity_rules', [
        'taxonomy_term' => ['allow_delete' => TRUE],  // this type only
      ]);
    ```

    The effective rule is `entity_rules[type].allow_delete ?? allow_delete`, so
    every other type (node, media, paragraph, menu, redirect, file, …) stays
    delete-denied. This is the **Sentinel** gate only — the agent's Drupal role
    must also grant the matching permission (e.g. `delete terms in <vocabulary>`);
    a delete needs **both** gates. The effective map is reported by
    `drupal_security_info` under `entityRules`.
- `allow_graphql_mutations: false` — JSON:API is the write plane; GraphQL is
  read-only for the agent.
- `denied_entity_types: [user]` — agents must not create or update user
  accounts.
- `allow_raw_sql` is left unset (i.e. `FALSE`) — raw SQL is refused. Leave it
  that way on production. The deny lists above are enforced above the entity
  API, so a raw statement is a different and weaker boundary: it reaches the
  tables behind those entity types directly. If a workflow genuinely needs SQL,
  see §3.7 rather than reaching for the connector's old ungoverned path, which
  no longer exists.

### 3.7 Raw SQL (only if a workflow requires it)

`drush sql:query` cannot be governed by Drupal at all — Drush caps its
bootstrap below the level at which module command files are discovered, so no
hook in any module runs on its path. Anything holding the SSH key can therefore
read every table regardless of policy, which is why the connector no longer
uses it.

The governed replacement is `drush mcp-sentinel:sql-query`. Enabling it takes a
deliberate change on **both** sides:

```bash
# Drupal: opt the profile in.
ddev drush php:eval "
  \Drupal\mcp_sentinel\Entity\McpPolicyProfile::load('agent_prod')
    ->set('allow_raw_sql', TRUE)->save();
"
```

```jsonc
// Connector: opt the site in (config/config.json).
"drushSsh": {
  "rawSql": "governed",
  "allowedCommands": ["mcp-sentinel:sql-query"]  // only if you pin this list
}
```

What the agent gets is narrow on purpose: a single `SELECT`, over tables
belonging to entity types the profile allows, with no reference to a redacted
field's column anywhere in the statement, no `SELECT *` on a table carrying
one, and no expressions beyond `COUNT()`. Every attempt is written to the audit
chain with its statement text — refusals included — and the command refuses to
run at all if audit logging is off.

Prefer the entity-API tools where they can answer the question. Raw SQL is a
reporting escape hatch, not a read plane.

### 3.6 JSON:API write plane

Enable JSON:API writes on the agent-facing site (internal hostname only):

```bash
ddev drush php:eval "
  \Drupal::configFactory()
    ->getEditable('jsonapi.settings')
    ->set('read_only', FALSE)
    ->save();
"
```

Ensure the reverse proxy blocks JSON:API write methods (`POST`/`PATCH`/`DELETE`)
from the public hostname. Only the internal VPN hostname should accept writes.

### 3.7 Register tools with OAuth scope enforcement

```bash
ddev drush mcp-sentinel:setup
ddev drush cr
```

Verify one tool:

```bash
ddev drush config:get mcp_server.mcp_tool_config.mcp_sentinel_node_operations
# Expected: third_party_settings.mcp_server_oauth.authentication_mode = required
#           third_party_settings.mcp_server_oauth.scopes[0] = mcp_write
```

### 3.8 Verify the bounded source contract

With a bearer token for the designated Consumer whose subject has `access mcp
sentinel context`, call:

```bash
curl -sS '<INTERNAL_BASE_URL>/drupal-mcp/readiness' \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' | jq
```

Ready returns HTTP 200 and `contract_ready: true`. A stable HTTP 503 reason
identifies missing local wiring. This response is deliberately bounded: its
`claims` object keeps policy effectiveness, evidence-chain verification, and
overall posture false. A green readiness response is not an assurance report.

### 3.9 Export configuration

```bash
ddev drush cex
# Review the diff before committing — do not commit the consumer's client
# secret (it lives in a Key entity, not in exported YAML).
```

---

## 4. The `X-MCP-Client` header

The connector sends `X-MCP-Client: drupal-mcp-connector/<version>`. This header
is **not an enforcement gate** — it is recorded in the audit log as the
`mcp_client` metadata field (a label only). Governance cannot be bypassed by
omitting the header; a non-agent request cannot be governed by adding it. No
site configuration is required for this header.

The label value defaults to `drupal-mcp-connector/<version>` and may be overridden
per environment via the connector's `MCP_CLIENT_ID` environment variable. This
changes only the **logged label** — it has no effect on authentication,
scope enforcement, or governance.

### Two distinct "client id" concepts — do not conflate

| Concept | Source | Role |
|---------|--------|------|
| **`X-MCP-Client` label** | connector env var `MCP_CLIENT_ID` (default `drupal-mcp-connector/<version>`) | **Cosmetic / audit-log only.** Never read for any security decision. |
| **OAuth Consumer `client_id`** | the `consumers` Consumer entity (e.g. `mcp-agent-prod`, §3.2) | **Security-relevant.** Identifies the token's issuing client; when Sentinel's `agent_oauth_clients` allowlist is populated (§3.3) it is matched against **this** id to scope governance to a specific consumer. |

Changing `MCP_CLIENT_ID` does **not** change which consumer the OAuth token is
issued under, and must never be expected to affect governance, the
`agent_oauth_clients` allowlist, or scope checks. To restrict governance to a
specific client, set the **Consumer `client_id`** in `agent_oauth_clients`, not
the header label.

---

## 5. Governance keys + role-selects-profile

Once a request is on the agent channel (OAuth token passes §3 checks):

1. `McpPolicyResolver::isGoverned()` returns `TRUE` (channel is the trigger).
2. `McpPolicyResolver::resolve()` selects the profile by the **account's roles**
   (`TokenAuthUser::getRoles()` returns the OAuth subject's roles). This means
   different admins can have different policy profiles based on their Drupal role.
3. Audit log entries are attributed to the **acting admin** (the OAuth subject
   = `currentUser`). No extra configuration is needed; this is automatic.

---

## 6. End-to-end verification procedure

This procedure requires a live consumer and IdP configured per §3. It is a
manual runbook — record the results in an ops ticket or this section.

### Prerequisites

- Consumer `mcp-agent-<env>` created with `mcp_read` + `mcp_write` scopes.
- Agent policy profile with `allow_write: true`, `allow_delete: false`.
- JSON:API `read_only: false` on the internal host.
- `drush mcp-sentinel:setup` run; `drush cr` done; authenticated
  `/drupal-mcp/readiness` returns `contract_ready: true`.

### Step 1 — Obtain a token

```bash
# authorization_code flow (abbreviated; use a PKCE-capable client in practice)
TOKEN=$(curl -s -X POST '<INTERNAL_BASE_URL>/oauth/token' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<CLIENT_ID>' \
  -d 'client_secret=<CLIENT_SECRET>' \
  -d 'scope=mcp_read mcp_write' \
  | jq -r '.access_token')
echo "Token: $TOKEN"
```

### Step 2 — JSON:API write (internal host, Bearer token, no X-MCP-Client)

```bash
curl -s -X POST '<INTERNAL_BASE_URL>/jsonapi/node/article' \
  -H 'Authorization: Bearer '"$TOKEN" \
  -H 'Content-Type: application/vnd.api+json' \
  -H 'Accept: application/vnd.api+json' \
  -d '{
    "data": {
      "type": "node--article",
      "attributes": {"title": "Agent test node"}
    }
  }' | jq '.data.id // .errors'
```

**Expected:** `201 Created` with the new node's UUID. If the profile denies
the entity type, expect a `403 Forbidden`.

### Step 3 — Content-lock check

Acquire a content lock on the created node via the `mcp_sentinel_content_lock`
tool, then attempt a second write to the same node with a different token.
Expected: the second write is blocked with a `409 Conflict` (or the tool
returns a lock-conflict message).

### Step 4 — Audit attribution

```bash
ddev drush php:eval "
  \$rows = \Drupal::database()
    ->select('mcp_sentinel_audit_log', 'a')
    ->fields('a', ['uid', 'operation', 'entity_type', 'timestamp'])
    ->orderBy('timestamp', 'DESC')
    ->range(0, 5)
    ->execute()
    ->fetchAll();
  print_r(\$rows);
"
```

**Expected:** the most recent row has `uid` = the admin user whose token was
used (the OAuth subject). Confirm the `uid` matches `SELECT uid FROM users_field_data WHERE name = '<admin>'`.

### Step 5 — Cookie-session admin UI (must NOT be governed)

Log in to `<INTERNAL_BASE_URL>/user/login` as the same admin via browser cookie
session. Create or edit a node via `/node/add/article` in the Drupal admin UI.
**Expected:** the operation succeeds without any MCP Sentinel governance
(no audit row for the cookie-session write, no access denial).

### Pass criteria

| Check | Expected result |
|-------|-----------------|
| Bearer token write | `201 Created` (profile allows write) |
| Bearer token write to denied type (`user`) | `403 Forbidden` |
| Bearer token delete | `405 Method Not Allowed` or `403 Forbidden` (allow_delete = false) |
| Content-lock conflict | `409 Conflict` / lock-denied message |
| Audit row `uid` | Matches the acting admin (OAuth subject) |
| Cookie-session UI write | `2xx` success, NO new audit row |

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| All requests ungoverned | `agent_oauth_clients` + `agent_scopes` mismatch | Check token scopes: `jq -R 'split(".") \| .[1] \| @base64d \| fromjson' <<< "$TOKEN"` |
| 401 on every tool call | token lacks the exact scope or Consumer binding | Verify the token/Consumer/account/profile join and run `ddev drush mcp-sentinel:setup`; do not disable OAuth. |
| 503 from `/drupal-mcp/readiness` | source contract incomplete | Use the stable `reason` value and Status report; fix the named server/bridge/OAuth/audit/Tool/Consumer/account/profile prerequisite. |
| Audit row shows `uid: 0` | Consumer has no subject user (client_credentials) | Create a dedicated machine-account user and link it to the Consumer entity |
| APCu stale after config change | php-fpm has its own APCu pool | `ddev restart` to flush |
| Container still uses old service signature | Drupal container cache | `ddev drush cr` |
