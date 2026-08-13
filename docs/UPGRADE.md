# Upgrading MCP Sentinel

This document collects breaking changes and the migration steps they require.
For first-time installation see `../INSTALL.md`; for the connector/OAuth contract
see `CONNECTOR.md`.

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
