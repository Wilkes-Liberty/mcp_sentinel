# Upgrading MCP Sentinel

This document collects breaking changes and the migration steps they require.
For first-time installation see `../INSTALL.md`; for the connector/OAuth contract
see `CONNECTOR.md`.

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
`agent_scopes`. If the names disagree, the request is treated as *not* on the
agent channel — governance never engages and write tools effectively fail open
as ungoverned.

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
   drush mcp-sentinel:setup --require-oauth
   drush cr
   ```

5. **Mint fresh tokens.** Tokens issued before the migration still carry the old
   colon scope names; reissue them so they carry `mcp_read` / `mcp_write`.

6. **Verify.** Confirm a write request is governed again:

   ```bash
   drush mcp-sentinel:status
   ```
