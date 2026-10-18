# Installing MCP Sentinel

MCP Sentinel governs AI-agent traffic that reaches Drupal over the MCP Tool API,
JSON:API, and GraphQL. It does not connect any agent itself — install it
*alongside* whatever exposes your site to agents, then configure a policy.

This document covers installation, dependencies, submodule enablement, the
OAuth/connector pointers, and the reverse-proxy requirement for IP allowlisting.
See `README.md` for feature-by-feature configuration and `API.md` for the
extension points.

## Requirements

- Drupal 10.6+ or Drupal 11.3+ — the branches upstream still supports.
- PHP matching your Drupal core requirement.

### Hard dependencies (installed automatically by Composer)

These are required because the module calls their PHP APIs directly:

- `drupal/tool` — the Tool API the Sentinel Tool plugins extend.
- `drupal/key` — stores the webhook signing secret and (optionally) the audit
  encryption key **outside** exported configuration.
- `drupal/encrypt` — provides Encryption Profiles for optional at-rest
  encryption of audit metadata.
- `drupal/simple_oauth` and `drupal/consumers` — the OAuth agent channel that
  governance keys on (bearer token + agent scope).
- Drupal core `user`, `node`, and `jsonapi`.

### Strongly recommended (optional)

- `drupal/mcp_server` — exposes the Sentinel Tool plugins to MCP clients via the
  `mcp_sentinel_server` submodule. It currently has **no tagged stable release**,
  so it is a `require-dev`/`suggest` dependency only; see the note on
  `minimum-stability` in `README.md`.
- `drupal/graphql_compose` — enables the `mcp_sentinel_graphql` submodule.
- `drupal/charts` — optional. Upgrades the governance dashboard's built-in
  inline-SVG charts to interactive, exportable charts. Install it together with a
  charts library submodule (for example `charts_chartjs`) and enable both:
  `composer require drupal/charts` then `drush en charts charts_chartjs -y`. The
  dashboard renders correctly without it — `McpChartRenderer` falls back to
  self-contained inline SVG when the `charts` module is absent or when it is
  enabled without a library plugin.

## 1. Install with Composer

Base module only:

```bash
composer require drupal/mcp_sentinel
```

With the MCP Server integration (for exposing Tool plugins to MCP clients):

```bash
composer require drupal/mcp_sentinel drupal/mcp_server drupal/simple_oauth
```

> **mcp_server 2.x requires a patch to `mcp/sdk`** that adds the runtime element
> handler interfaces the Tool bridge depends on. The patch ships inside the
> mcp_server project at
> `.gitlab-ci/patches/mcp-sdk-runtime-handlers.patch`. Register it with
> `cweagans/composer-patches` for the `mcp/sdk` package and reinstall/repatch.
> See `README.md` → Installation for the exact steps.

## 2. Enable the modules (in order)

Enable the base module first, then the submodules you need. The base module
provides all governance, audit, content locks, and webhooks **without** any
submodule.

```bash
# Base module.
drush en mcp_sentinel -y

# Optional base feature, required for a production MCP Tool path. The OAuth
# submodule is mandatory for connector-facing production readiness.
drush en mcp_sentinel_server mcp_server_tool_bridge mcp_server_oauth -y

# Optional: govern the GraphQL Compose endpoint.
drush en mcp_sentinel_graphql -y

# Optional: human-approval gate for destructive operations.
drush en mcp_sentinel_approval -y

drush cr
```

## 3. Register the Tool plugins with mcp_server (if using mcp_sentinel_server)

```bash
# Production is fail closed by default: preflight every Tool, then register all
# of them with authentication_mode=required and the exact derived scope.
drush mcp-sentinel:setup

# Deliberate local-only escape. This always exits non-zero and never reports
# contract_ready; do not use it on staging or production.
drush mcp-sentinel:setup --allow-unauthenticated-development
```

`drush mcp-sentinel:teardown` reverses this (unregisters all Sentinel tools).

## 4. Set up the Paladin trust model

From 3.0, governed tools fail closed unless the request carries a verified
Paladin identity (`iss`, `sub`, `azp` or `act.sub`) plus a `tenant`. OAuth is
transport only: a bearer delivers that Paladin principal; it is not itself a
governed identity. Governance is decided server-side from the sealed principal,
never from a client-supplied header.

Configure `simple_oauth` as the transport:

1. Create the required OAuth scope entities and an enabled role-bound policy
   profile.
2. Run `drush mcp-sentinel:agent-provision <tier> --env=<env>` to create or bind
   the role, service account, and exact designated Consumer. The command never
   creates or rotates a secret; set that out of band.
3. Mint a Paladin token (carried as a `simple_oauth` bearer) with `iss`, `sub`,
   `azp` (or `act.sub`), `tenant`, and the exact required scope.
4. The agent sends `Authorization: Bearer …` on every request. Sentinel seals
   the Paladin principal from that token and then resolves the policy profile.

Cookie-session administrators and role-fallback sessions are not a
governed-tool identity. Role-fallback (`governed_role_fallback`) remains only
as the JSON:API/GraphQL session caveat: those HTTP surfaces apply the
principal refusal when the request already carries a validated bearer; a
role-fallback session on those paths is unchanged. The companion Node.js
connector is documented separately in `docs/CONNECTOR.md`.

> **Scope-name convention.** The `agent_scopes` you configure here must match the
> scope **machine-ids** of your `oauth2_scope` entities exactly. simple_oauth
> scope machine-ids are conventionally underscore-separated, and the underscore
> form is the default: fresh installs ship
> `agent_scopes: [mcp_read, mcp_write, mcp_config, mcp_config_read]`
> (`mcp_config_read` gates config *read* — `config_get`/`config_list` — to a
> read-only auditor/dev tier; `mcp_config` gates config *write* — `config_set` —
> to the dev/config tier).
> Most sites need no change here. Only if your scope ids use a *different* naming
> — for example legacy colon-form scopes (`mcp:read` / `mcp:write`) created
> before this convention was standardized — must you either set `agent_scopes` to
> match those ids, or (recommended) migrate the scopes to the underscore form per
> [§ "Upgrade note: OAuth scope machine ids are now underscores"](#upgrade-note-oauth-scope-machine-ids-are-now-underscores).
> If nothing matches, the source contract is not ready and governed product
> paths are refused — see the fail-closed note below.

> **Fail-closed safety net.** The settings page, Status report, authenticated
> `GET /drupal-mcp/readiness`, Tool base, context endpoint, and governed
> JSON:API/GraphQL subscribers all use one typed source-contract evaluator.
> Missing server/bridge/OAuth/audit wiring, empty scopes, absent or disabled
> Tool registrations, an undesignated/disabled Consumer, blocked owner, or no
> applicable active role-bound profile produces a stable not-ready reason and
> refuses the governed path. `contract_ready` means only that this local
> configuration and availability contract is complete; it does not claim
> policy effectiveness, verified evidence, or overall security posture.

> **Agent discovery.** Once the agent channel is wired, agents can introspect
> your content model before acting via the governed context endpoint
> `/drupal-mcp/context` (content types, fields, vocabularies, media types);
> `/drupal-mcp/health` is a liveness probe, while authenticated
> `/drupal-mcp/readiness` reports the bounded source contract. These are
> described in `docs/CONNECTOR.md`.

## 5. Set up audit-metadata encryption (optional but recommended)

The `metadata` column of every audit row can be encrypted at rest:

1. `drush en encrypt -y` (installed as a hard dependency, just enable it).
2. Create a Key entity at **Configuration → System → Keys** using a File or
   Environment key provider so the secret never enters exported config.
3. Create an Encryption Profile at **Configuration → System → Encryption →
   Encryption Profiles** pointing at that key.
4. In **Configuration → Web services → MCP Sentinel** → *Audit Logging*, select
   your Encryption Profile and save. New rows are encrypted; existing plaintext
   rows remain readable (no data migration needed).

## 6. Configure a policy

Open **Configuration → Web services → MCP Sentinel**
(`/admin/config/services/mcp-sentinel`):

1. Enable the master switch.
2. Choose the OAuth/role governance model.
3. Create one or more **policy profiles** (read/write/delete gates, allowed and
   denied entity types, redacted fields, rate limits, exfiltration caps, IP
   allowlists).
4. Configure audit logging, DLP, anomaly rules, and webhook endpoints as needed.

Review the active policy and audit/lock counts at any time:

```bash
drush mcp-sentinel:status
drush mcp-sentinel:verify
```

`mcp-sentinel:verify` is the evidence document for the secure-install
claim. It does not write content. Add `--live` to also run the
hostile-input probes (still no writes). See `docs/verification.md`.

## Reverse-proxy / trusted-proxy requirement for IP allowlisting

Per-profile IP allowlisting compares the **client** IP against a CIDR list. If
Drupal runs behind a load balancer, CDN, or reverse proxy, the immediate peer is
the proxy — not the agent — so you **must** configure Drupal's trusted-proxy
settings or every request will appear to come from the proxy.

In `settings.php`:

```php
$settings['reverse_proxy'] = TRUE;
$settings['reverse_proxy_addresses'] = ['10.0.0.1', '10.0.0.2']; // your proxies
```

Without correct trusted-proxy configuration, the `X-Forwarded-For` header is
**not** trusted (by design — this prevents IP spoofing), and the allowlist will
match the proxy address. See `README.md` → *IP allowlisting per profile* for the
full explanation and spoofing-protection details.

## Paladin operator-bind introspection

Every kill-switch Drush command introspects a Paladin access token.
The URL, issuer, audience, operator audience, and client credentials
are pinned in `settings.php`, not in exported config, so a config
import cannot redirect introspection. HTTPS and HTTP Basic client
authentication are required. Missing any of these fails closed.

```php
$settings['mcp_sentinel.paladin.introspection_url'] = 'https://idp.example/realms/agents/protocol/openid-connect/token/introspect';
$settings['mcp_sentinel.paladin.issuer'] = 'https://idp.example/realms/agents';
$settings['mcp_sentinel.paladin.audience'] = 'mcp-sentinel-operator-bind';
$settings['mcp_sentinel.paladin.operator_audience'] = 'mcp-sentinel-operator';
$settings['mcp_sentinel.paladin.client_id'] = 'mcp-sentinel-introspect';
$settings['mcp_sentinel.paladin.client_secret'] = 'the-introspection-client-secret';
```

The token is passed as `PALADIN_TOKEN` or on stdin, never `--token`.
Pass `--operator=<Drupal account name>` on every command. Bind that
account first with `mcp-sentinel:operator-bind`. The introspection
response must be `active` with a numeric future `exp`, `iss` must
match the pinned issuer, `aud` / `azp` / `client_id` must match the
pinned audience, and `aud` or a role claim must match
`operator_audience`. `azp` and `client_id` are not operator-audience
matches. A token with an `act` or `actor` claim is refused. A 3xx
from Paladin is refused; the token is never sent to a hop. Paladin
down fails closed.

The kill-block default is 24 hours; the maximum is 7 days.
Token lifetimes are set at the issuer; see docs/kill-switch.md.

Optional bind claim pins (defaults shown):

```php
$settings['mcp_sentinel.paladin.operator_name_claim'] = 'preferred_username';
$settings['mcp_sentinel.paladin.operator_mail_claim'] = 'email';
```

A mail-type name claim (`email` / `mail`) is refused unless the
mail claim is also pinned. When a mail claim is pinned, the token
must carry `email_verified === true` and that mail must match the
Drupal account.

Run database updates: 10034 adds the Drupal uid column on
`mcp_sentinel_operator_binding`. 10036 adds hold-queue columns
and the escalation stamp. Drain or review the webhook queue
before updb: keyless pending rows are held when any kill-block
or freeze is active. 10037 resets Paladin uids so every operator
must re-bind with a matching token, drops leftover Drush binding
rows, keeps Drush-requested freezes, and reverts Drush-requested
unkills. Every kill command, including break-glass, refuses every
operator until they re-bind. 10037 also adds a generated
`uid_nonzero` column plus a unique index on MySQL/MariaDB (a
partial unique index on SQLite and PostgreSQL). Settings
`mcp_sentinel.allow_drush_os_assertion` and
`mcp_sentinel.web_server_user` are ignored.

To restore a uid, read `previous_uid` and `identity_hash` from
the `operator_binding_uid_reset` HMAC row (audit UI or
`McpAuditLogger::decodeMetadata()` on `audit_chain_log.metadata`),
then `UPDATE {mcp_sentinel_operator_binding} SET uid = :previous_uid
WHERE identity_hash = :identity_hash`. A restore re-trusts a
binding that never passed the Paladin claim check. The unique
index refuses a restore that collides with another uid > 0 row.
Rolling the module code back without a matching down hook leaves
the unique index and, on MySQL, `uid_nonzero`. 10032 and 10033
delete dead `paladin_introspection_*` keys if an earlier update
wrote them into importable config. 10038 is reserved for a
DEV-985 follow-up.

## Updating

From 3.0, incomplete source-contract wiring and a missing Paladin principal fail closed.

After pulling a new release, run database updates and rebuild caches:

```bash
drush updb -y
drush cr
```

Then verify the audit hash chain survived the update:

```bash
drush mcp-sentinel:audit-verify
```

### Upgrade note: OAuth scope machine ids are now underscores

MCP Sentinel standardized its OAuth scope machine ids on the **underscore**
convention: `mcp:read` → `mcp_read` and `mcp:write` → `mcp_write`. This is a
**contract change**. Governance matches the scope *name* carried on a validated
token against `mcp_sentinel.settings:agent_scopes`, so the token, the
`mcp-sentinel:setup` tool tags, and the governance allowlist must all agree.

Fresh installs need no action — the install default and `mcp-sentinel:setup`
already use the underscore form. **If you previously created colon-form
(`mcp:read` / `mcp:write`) scopes you must migrate**. Legacy releases could
treat the mismatch as ungoverned; the current source contract refuses the
governed product path as not ready:

1. Update the governance allowlist to the underscore form (UI: **Configuration →
   Web services → MCP Sentinel → OAuth agent channel → Agent scopes**, one per
   line), or via drush:

   ```bash
   drush php:eval "\Drupal::configFactory()->getEditable('mcp_sentinel.settings')->set('agent_scopes', ['mcp_read', 'mcp_write'])->save();"
   ```

2. Rename the `simple_oauth` scope entities so their **`name` equals the
   underscore machine `id`**. The simplest path is to delete the old colon-form
   scopes and recreate them per `docs/CONNECTOR.md` §3.1 (with `id` and `name`
   both set to `mcp_read` / `mcp_write`), then re-grant them on each consumer.

3. Update each consumer's granted `scopes` to `['mcp_read', 'mcp_write']`
   (UI: **Configuration → Web services → Consumers**, or via `drush php:eval`).

4. Re-tag the registered tools and rebuild caches:

   ```bash
   drush mcp-sentinel:setup
   drush cr
   ```

5. Mint fresh tokens (existing tokens carry the old colon scope names) and
   confirm a write tool is governed again via `drush mcp-sentinel:status`.

See `docs/UPGRADE.md` for the full step-by-step.

## Uninstalling

```bash
drush pmu mcp_sentinel_server mcp_sentinel_graphql mcp_sentinel_approval -y
drush pmu mcp_sentinel -y
```

Uninstall removes the Sentinel database tables, the module configuration, and
the `mcp_api` role, leaving no orphaned footprint.
