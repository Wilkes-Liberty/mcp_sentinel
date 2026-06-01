# MCP Sentinel — Connector ↔ Drupal Contract & Per-Environment Runbook

> **Audience:** DevOps / platform engineers wiring the `drupal-mcp-server`
> connector to a Drupal site protected by MCP Sentinel. This document covers
> the authorization model, per-environment configuration steps, and the
> end-to-end manual verification procedure.

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
drupal-mcp-server connector
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

- `access_token_expiration` ≤ `3600` seconds.
- Refresh tokens enabled (`use_refresh_tokens: true`, TTL ≥ 7 days).

---

## 2. Per-tool scope enforcement

Each `mcp_tool_config` entity carries third-party settings under the
`mcp_server_oauth` namespace (written by
`drush mcp-sentinel:setup --require-oauth`):

| Setting | Value |
|---------|-------|
| `authentication_mode` | `required` |
| `scopes` | `mcp:read` (read/explain tools) or `mcp:write` (write tools) |

The `mcp_server_oauth` subscriber enforces these per tool call — a token that
lacks the required scope is rejected before governance even fires.

### Tool → scope mapping

| Tool | Scope |
|------|-------|
| `mcp_sentinel_site_context` | `mcp:read` |
| `mcp_sentinel_security_policy` | `mcp:read` |
| `mcp_sentinel_graphql_schema` | `mcp:read` |
| `mcp_sentinel_content_lock` | `mcp:write` |
| `mcp_sentinel_node_operations` | `mcp:write` |
| `mcp_sentinel_media_create` | `mcp:write` |
| `mcp_sentinel_workflow_transition` | `mcp:write` |
| `mcp_sentinel_bulk_operations` | `mcp:write` |

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

> **Security note:** The JSON:API write plane and the `/oauth/token` endpoint
> must be exposed **only** on an internal VPN hostname, never on the
> public-facing URL. Enforce this at the reverse proxy / load balancer.

### 3.1 Scope entities

Create two simple_oauth scope entities (or use `simple_oauth_static_scope` for
static scope definitions):

```bash
# mcp:read
ddev drush php:eval "
  \$scope = \Drupal\simple_oauth\Entity\Oauth2Scope::create([
    'id' => 'mcp_read',
    'name' => 'mcp:read',
    'description' => 'MCP read/explain tools',
    'grant_types' => [
      'authorization_code' => ['status' => TRUE],
      'client_credentials' => ['status' => TRUE],
    ],
    'umbrella' => FALSE,
  ]);
  \$scope->save();
"

# mcp:write
ddev drush php:eval "
  \$scope = \Drupal\simple_oauth\Entity\Oauth2Scope::create([
    'id' => 'mcp_write',
    'name' => 'mcp:write',
    'description' => 'MCP write tools',
    'grant_types' => [
      'authorization_code' => ['status' => TRUE],
      'client_credentials' => ['status' => TRUE],
    ],
    'umbrella' => FALSE,
  ]);
  \$scope->save();
"
```

### 3.2 Consumer (one per environment)

Create a Consumer entity named `mcp-agent-<env>` via the Drupal UI at
`/admin/config/services/consumer/add`, or via `drush php:eval`:

```bash
ddev drush php:eval "
  \$c = \Drupal\consumers\Entity\Consumer::create([
    'label' => 'MCP Agent (staging)',
    'client_id' => 'mcp-agent-staging',
    'is_default' => FALSE,
    'redirect' => ['https://PLACEHOLDER-staging.internal/oauth/callback'],
    'scopes' => ['mcp_read', 'mcp_write'],
    'access_token_expiration' => 3600,
    'confidential' => TRUE,
  ]);
  \$c->save();
  echo 'Consumer UUID: ' . \$c->uuid() . PHP_EOL;
"
```

Note the generated `client_id` and set the client secret via the consumer edit
form (stored in a Key entity, never in config YAML).

### 3.3 MCP Sentinel agent-channel settings

Register the consumer with MCP Sentinel (optional but recommended — restricts
governance to exactly this consumer rather than any token bearing `mcp:*`):

```bash
ddev drush php:eval "
  \Drupal::configFactory()
    ->getEditable('mcp_sentinel.settings')
    ->set('agent_oauth_clients', ['mcp-agent-staging'])
    ->save();
"
```

> **Important:** with the default config `agent_oauth_clients: {}` (empty),
> ANY OAuth token bearing `mcp:read` or `mcp:write` from ANY consumer is
> treated as on the governed agent channel. To restrict governance to a
> specific consumer, populate `agent_oauth_clients` with its `client_id`.

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
    ->set('roles', ['mcp_api'])           // bound to the admin's governed role
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
- `allow_graphql_mutations: false` — JSON:API is the write plane; GraphQL is
  read-only for the agent.
- `denied_entity_types: [user]` — agents must not create or update user
  accounts.

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
ddev drush mcp-sentinel:setup --require-oauth
ddev drush cr
```

Verify one tool:

```bash
ddev drush config:get mcp_server.mcp_tool_config.mcp_sentinel_node_operations
# Expected: third_party_settings.mcp_server_oauth.authentication_mode = required
#           third_party_settings.mcp_server_oauth.scopes[0] = mcp:write
```

### 3.8 Export configuration

```bash
ddev drush cex
# Review the diff before committing — do not commit the consumer's client
# secret (it lives in a Key entity, not in exported YAML).
```

---

## 4. The `X-MCP-Client` header

The connector sends `X-MCP-Client: drupal-mcp-server/<version>`. This header
is **not an enforcement gate** — it is recorded in the audit log as a label
only. Governance cannot be bypassed by omitting the header; a non-agent request
cannot be governed by adding it. No site configuration is required for this
header.

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

- Consumer `mcp-agent-<env>` created with `mcp:read` + `mcp:write` scopes.
- Agent policy profile with `allow_write: true`, `allow_delete: false`.
- JSON:API `read_only: false` on the internal host.
- `drush mcp-sentinel:setup --require-oauth` run; `drush cr` done.

### Step 1 — Obtain a token

```bash
# authorization_code flow (abbreviated; use a PKCE-capable client in practice)
TOKEN=$(curl -s -X POST '<INTERNAL_BASE_URL>/oauth/token' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=<CLIENT_ID>' \
  -d 'client_secret=<CLIENT_SECRET>' \
  -d 'scope=mcp:read mcp:write' \
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
| 401 on every tool call | `mcp_server_oauth` not enabled or `authentication_mode` mismatch | `ddev drush en mcp_server_oauth -y && ddev drush mcp-sentinel:setup --require-oauth` |
| Audit row shows `uid: 0` | Consumer has no subject user (client_credentials) | Create a dedicated machine-account user and link it to the Consumer entity |
| APCu stale after config change | php-fpm has its own APCu pool | `ddev restart` to flush |
| Container still uses old service signature | Drupal container cache | `ddev drush cr` |
