# Upgrading MCP Sentinel

This document collects breaking changes and the migration steps they require.
For first-time installation see `../INSTALL.md`; for the connector/OAuth contract
see `CONNECTOR.md`.

## Principal-key actor slot no longer mixes azp and act.sub

`McpPrincipalKey::fromClaims()` keeps non-delegated keys as
`iss|sub|azp` (no prefix). A delegated actor is stored as
`act:` plus top-level `act.sub`, so `azp=X` and `act.sub=X` compose
different keys (`iss|sub|X` vs `iss|sub|act:X`). An `azp` that
already starts with `act:` (any case) is refused
(`actor_claim_collision`). Same-token `azp=X` with `act.sub=X` is
allowed; it composes the delegated key. Dispatch writes
`denied_access` with reason `actor_claim_collision` for the prefix
collision; the caller still sees the generic missing-principal
refusal.

No `updatedb` and no row rewrite. Stored `X` cannot be proven to
have been `azp` versus `act.sub`, so kill-switch matching and
webhook hold selection permanently treat `iss|sub|X` and
`iss|sub|act:X` as the same stop. That pairing is fail-closed and
over-inclusive (over-block only, never under-block): a new
`iss|sub|act:X` stop also refuses a non-delegated `azp=X` token,
and a new `iss|sub|X` stop also refuses a delegated `act.sub=X`
token, for as long as this module is installed. Individual stops
still expire at their TTL; the pairing itself is not bounded to
pre-upgrade rows. Audit and stored `principal_key` identity stay
separated (`iss|sub|X` versus `iss|sub|act:X`). A new `act:` stop
also holds webhook rows and carried jobs stored under the
unprefixed key. Rebuild caches (`drush cr`).

Policy profiles and designated-client matching still use the OAuth
`client_id` / `azp` allowlist, not this actor slot. Request-rate
flood keys still use the server-resolved uid. The language-neutral
vectors in `tests/fixtures/principal-key-vectors.json` now expect
the `act:` prefix on delegated keys; a JS twin of `fromClaims()`
must match, including the raw `act.sub` cap and the 770-character
composed-key bound. Product code always emits lowercase `act:`. Webhook
hold selection uses SQL `IN` on those aliases; a MySQL `*_ci`
collation can still over-hold a whole-key case fold, which predates
this prefix. Dual-match strips one `act:` prefix only:
`iss|sub|act:act:X` pairs with `iss|sub|act:X`, not with
`iss|sub|X`. Operator-supplied `ACT:X` is stored as `act:X`.
`holdMatching` uses that same set, so a stop of `iss|sub|act:X`
does not select a pending row stored as `iss|sub|act:act:X`.
Send-time `shouldHoldRow` still holds that row because the
stored key's aliases include `iss|sub|act:X`. Product code
emits `act:act:X` only when `act.sub` is itself `act:X`.

**Upgrade:** operators do not need to re-issue active delegated
stops across this deploy. Dual-match keeps a pre-upgrade
`--principal-key=iss|sub|<act.sub>` stop in force, and a new
`iss|sub|act:<act.sub>` stop holds backlog stored under the old
spelling. Prefer the prefixed form for new delegated stops.
`parsePrincipalKey` still accepts the unprefixed three-part form;
that stop now enforces both spellings. A composed principal
key longer than 770 characters (`McpKillSelector::MAX_KEY_LENGTH`)
is refused (`part_too_long`): a 256/256/252 delegated token
is exactly 770 and stays accepted; a 256/256/256 token is
774 and is refused. `kill-status` and
`unkill` still match the stored row's exact spelling. If
enforcement refuses a token under a legacy `iss|sub|X` stop,
status or unkill with `iss|sub|act:X` finds no row. Use the
stored spelling.

**Rollback:** revert the module and rebuild caches. Dual-match goes
away with the revert, so exact sha256 matching returns. Kill-switch
rows and webhook keys written with the `act:` prefix after this
change will not match the old unprefixed lookup. Re-issue those
delegated stops as `iss|sub|<act.sub>` if the previous code is
restored. No `updatedb` to undo.

## Sealed-token authentication denials are written to audit_chain

`McpSealedTokenManager::verify()` and
`McpSealedTokenAuthProvider::authenticate()` write a
`denied_access` row (`tool: sealed_token`) on every denial.
Repeat denials of the same reason and principal share
one row per 60-second window (`sealed_token_deny_audit_window`
on `mcp_sentinel.settings`; 1..3600, default 60). Rebuild
caches (`drush cr`). No `updatedb`; 10039 is unchanged.
`McpSealedTokenManager` gained a `McpSealedTokenDenialAuditor`
constructor argument. Until the container is rebuilt, resolving
the manager fails with a TypeError.

## Sealed-token auth provider first argument is a \Closure; a third \Closure logger was added

The first argument of `McpSealedTokenAuthProvider` changed from
`McpSealedTokenManager` to a `\Closure` (service closure for
`mcp_sentinel.sealed_token_manager`) and a third `\Closure` logger
argument was added. Rebuild caches (`drush cr` or `drush updb`)
after updating. Until the container is rebuilt, the cached
container passes the old argument and every web request fails with
a TypeError in McpSealedTokenAuthProvider. Drush does not resolve
`authentication_subscriber`, so `drush cr` / `drush updb` still
recover the site. No update hook; 10039 is unchanged.

## Context and GraphQL operations require a principal

A role-fallback session is no longer enough on these paths. Each one
refuses the call unless the request has a verified principal and tenant:

- GraphQL operations
- `/drupal-mcp/context` (the readiness probe is unchanged)

JSON:API and the GraphQL HTTP seam require that principal only when
the request already carries a validated bearer. A role-fallback
session on those two paths is unchanged.

`drush mcp-sentinel:sql-query` does not take a bearer. A local
invocation stays on the profile SQL guard (`allow_raw_sql` still
ships off). A process that already sealed a job principal is refused
when that seal has no principal or tenant. Do not pass `iss`, `sub`,
or `tenant` as command options.

The principal is `iss`, a `sub` that is not the Drupal user id, `azp`
or top-level `act.sub`, and `tenant`. A sealed token minted with a
tenant already qualifies. A Simple OAuth access token is stamped onto
`mcp_sentinel.token_claims` only when simple_oauth's resource server
accepts that bearer and the verified payload already contains those
claims. This module does not add an issuer, JWKS, or audience setting,
and it does not copy the Drupal user id into `sub`.

The other `mcp-sentinel:*` commands are unchanged. `drush sql:query`,
`sql:cli`, `sql:dump`, and `php:eval` still run below module discovery
and are still not governed.

Rebuild caches after deploy. The JSON:API and GraphQL subscribers and
the context controller fail closed if a cached container still has the
previous argument list. `mcp-sentinel:sql-query` gained a required
principal-dispatcher argument and will not construct until that rebuild.

## Translation inventory reads each language from its latest-affected revision

`GET .../mcp-translations` still returns `meta.working.vid` as the tip
revision, but each `working.translations[]` row is now filled from that
language's latest translation-affected revision (`working_vid`), not from
the tip. After revise-over-working, a language whose draft sits on an
earlier revision reports `moderation_state: draft` and `pending: true`
instead of the tip's carried `published` moderation record.

New additive keys: `working_vid`, `pending`, `affected` on each working
language; `meta.pending`, `meta.multi_pending`, and `meta.notices` (code
`multi_pending_publish`) when more than one language is pending. Clients
that treated tip `moderation_state` as "no draft" should switch to
`pending` / `working_vid`. See `draft-continuation.md`.

The default language can now be revised over a named working copy the same
way a translation can. Continue of the default language also works when
the tip stores it as unpublished with published moderation.

## Config secrets are withheld, and secret-bearing names cannot be written

Values under sensitive key names (`password`, `token`, `key_value` and the rest
of the built-in list) are no longer written to the audit log or returned by
`mcp_sentinel_config_get`, at any depth. For `key.key.*`, `encrypt.profile.*`,
`simple_oauth.*` and `consumer.*` the audit log records changed paths only and
the get tool returns structure only, with `values_withheld` set.

- **`mcp_sentinel_config_set` now refuses those names.** A workflow that had an
  agent write a Key entity or an OAuth consumer through the tool stops working.
  Have a human make that change.
- **Audit rows already written are not rewritten.** The chain is append-only.
  If a governed agent saved a secret through config before this release, rotate
  that secret.
- **Pending approval requests keep their values.** A request for a
  secret-bearing name that was queued before this release is still pending and
  its sealed manifest still holds the values. Deny it and purge decided
  requests.
- Update `10025` adds `audit_sensitive_config_keys` and
  `audit_secret_config_prefixes`, both empty. They only add to the built-in
  lists.

## Governed config writes are validated before they are saved

`mcp_sentinel_config_set` used to save whatever a permitted agent sent. It now
validates the merged object first (typed config, then the config import
validators for that one object) and refuses the write on any violation. Writes
that saved before can be refused after this update:

- a value of the wrong type, a value that breaks a schema constraint, or a key
  the schema does not define;
- a value that the owning module's config import validator rejects;
- any write to an object whose active data already violates its schema. Fix the
  paths the refusal names, then retry;
- any write to a config name that has **no schema**. To keep writing such a
  name, turn on *Allow configuration write to names that have no schema*
  (`allow_schemaless_config_write`) on the profile that needs it. Update
  `10024` adds the key to existing profiles at `false`.

A pending approval request for a schema-less name that was queued before this
update is refused when approved. Ask the agent to submit it again.

Run `drush updb` and rebuild caches: the approval executor gained a constructor
argument.

## Governed MCP paths now refuse incomplete 2.3.0 wiring

**Affects:** every site upgrading from 2.3.0, especially installs that left
`agent_oauth_clients` empty or registered Tools with OAuth disabled/optional.

The upgrade does **not** silently designate a Consumer, enable an account,
select a policy profile, create/rotate a secret, or rewrite existing Tool auth
settings. Those are security decisions and hidden repair would make an
incomplete site appear safe. Instead one typed evaluator returns a stable
not-ready reason, and governed Tool/context/JSON:API/GraphQL product paths deny
until all prerequisites are true.

After deploying the code and running database updates:

1. Enable `mcp_sentinel_server`, `mcp_server_tool_bridge`, and
   `mcp_server_oauth`, then rebuild the container.
2. Ensure the four scope entities exist: `mcp_read`, `mcp_write`,
   `mcp_config_read`, and `mcp_config`.
3. Ensure an enabled policy profile applies to the selected tier role.
4. Run `drush mcp-sentinel:setup`. OAuth is required by default; the command
   preflights every Tool and rolls back a partial registration batch.
5. Run `drush mcp-sentinel:agent-provision <tier> --env=<env>`. It binds an
   enabled Consumer to an active owner account and designates the exact client
   ID as its final write. It never creates or rotates a secret.
6. Set the Consumer secret out of band, mint a fresh token, run `drush cr`, and
   call authenticated `GET /drupal-mcp/readiness`.

HTTP 200 with `contract_ready: true` proves only the local source-contract
configuration and availability checks. It does not claim policy effectiveness,
audit-chain verification, independent evidence, or an overall-green posture.
HTTP 503 carries a stable non-secret reason for the next missing prerequisite.

The only unauthenticated setup path is
`--allow-unauthenticated-development`. It is visibly development-only, exits
non-zero, and can never satisfy production readiness. Rolling code back does
not restore governed availability automatically; preserve the exported
configuration and complete or deliberately revert the identity/Tool changes as
an operator-controlled action.

## 2.0.0 requires the `audit_chain` module

**Affects:** any install upgrading from 1.x to 2.0.x.

2.0.0 moved the tamper-evident audit chain into its own project, so `audit_chain`
became a hard dependency.

From **2.0.2** onward the module handles this itself: the service reference is
optional at compile time, `drush updatedb` installs `audit_chain` if it is
missing, and the status report names the module if it is ever disabled. The
ordinary sequence works:

```bash
composer require drupal/mcp_sentinel:^2.0
drush updatedb -y
```

### If you are landing 2.0.0 or 2.0.1 specifically

Those two releases fail hard when `audit_chain` is not already enabled. The
container cannot compile:

```
The service "mcp_sentinel.audit_logger" has a dependency on
a non-existent service "audit_chain.logger".
```

The front end returns 500 and `drush` cannot recover the site, because drush
needs the same container. **Rolling back makes it worse** — at 1.13 `audit_chain`
is only a transitive requirement, so `composer require drupal/mcp_sentinel:^1.13`
removes it.

Install and enable the dependency *before* the code that needs it:

```bash
composer require drupal/audit_chain:^1.0.1
drush en audit_chain -y
composer require drupal/mcp_sentinel:^2.0
drush updatedb -y
```

Upgrading straight to 2.0.2 or later avoids this entirely.

## OAuth scope machine ids standardized to underscores (`mcp_read` / `mcp_write`)

**Affects:** any install that created OAuth scopes using the colon form
(`mcp:read` / `mcp:write`).

**What changed.** MCP Sentinel's OAuth scope machine ids now use the underscore
convention everywhere — the install default
(`config/install/mcp_sentinel.settings.yml`), the settings-form default, the
`mcp-sentinel:setup` tool→scope tags, and all documentation:

| Before    | After      |
|-----------|------------|
| `mcp:read`  | `mcp_read`  |
| `mcp:write` | `mcp_write` |

**Why it is a contract change.** Governance is decided server-side: the
`McpOauthContext` service reads the scope *names* carried on the
server-validated access token and intersects them with the
`mcp_sentinel.settings:agent_scopes` allowlist (see
`src/Service/McpOauthContext.php`). For a token to be recognised as the agent
channel, the scope **name** on the token must exactly match an entry in
`agent_scopes`. On legacy releases a mismatch could be treated as an ungoverned
request. The current source contract instead refuses the governed product path
with a stable not-ready/scope reason.

Because the scope name flows end-to-end (scope entity → token → governance
allowlist), the scope entity's `name` must equal its underscore machine `id`,
and `agent_scopes` plus the tool tags must use the same underscore strings.

### Fresh installs

No action required. The install default and `drush mcp-sentinel:setup` already
emit the underscore form.

### Migrating an existing install that used colon scopes

1. **Update the governance allowlist** to the underscore form.

   UI: **Configuration → Web services → MCP Sentinel → OAuth agent channel →
   Agent scopes** — one scope per line:

   ```
   mcp_read
   mcp_write
   ```

   Or via drush:

   ```bash
   drush php:eval "\Drupal::configFactory()->getEditable('mcp_sentinel.settings')->set('agent_scopes', ['mcp_read', 'mcp_write'])->save();"
   ```

2. **Rename the `simple_oauth` scope entities** so each scope's `name` equals its
   underscore machine `id`. The cleanest path is to delete the old colon-form
   scopes and recreate them with both `id` and `name` set to the underscore form
   (see `CONNECTOR.md` §3.1). Example for the read scope:

   ```bash
   drush php:eval "
     \$old = \Drupal\simple_oauth\Entity\Oauth2Scope::load('mcp_read');
     // If your old entity used a colon name, fix the name in place:
     if (\$old && \$old->getName() !== 'mcp_read') {
       \$old->set('name', 'mcp_read')->save();
     }
   "
   ```

   (Repeat for `mcp_write`. If your old scopes were keyed by a colon-form id,
   delete and recreate them per CONNECTOR.md §3.1 instead.)

3. **Update each consumer's granted scopes** to the underscore form.

   UI: **Configuration → Web services → Consumers** → edit the agent consumer →
   set scopes to `mcp_read` + `mcp_write`. Or via drush:

   ```bash
   drush php:eval "
     \$c = \Drupal::entityTypeManager()->getStorage('consumer')->loadByProperties(['client_id' => 'mcp-agent-staging']);
     \$c = reset(\$c);
     \$c->set('scopes', ['mcp_read', 'mcp_write'])->save();
   "
   ```

4. **Re-tag the registered tools and rebuild caches:**

   ```bash
   drush mcp-sentinel:setup
   drush cr
   ```

5. **Mint fresh tokens.** Tokens issued before the migration still carry the old
   colon scope names; reissue them so they carry `mcp_read` / `mcp_write`.

6. **Verify.** Confirm a write request is governed again:

   ```bash
   drush mcp-sentinel:status
   ```
