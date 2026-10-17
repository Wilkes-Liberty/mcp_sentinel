# Agent kill switch

The kill switch lets an operator stop an agent from acting on your site.
This page explains what it does, how to set it up, and how to issue,
confirm, check, and lift a stop.

The kill switch shipped in release 3.2.0. Identity and the Drush
commands on this page describe the current `1.x` branch (DEV-986),
which is listed under Unreleased in `CHANGELOG.md`. The section
[Planned (DEV-985)](#planned-dev-985) describes work that is not in any
release.

## What it does

A stop is a row in a registry table called `mcp_sentinel_kill_block`.

A stop targets one of three things:

| Stop | Selector | What it covers |
| --- | --- | --- |
| One agent | `--principal-key=iss\|sub\|actor` | One agent acting for one person. |
| Person-wide | `--human-key=iss\|sub` | Every agent acting for that person. |
| Tenant-wide | `--tenant=TENANT` | Every agent whose token carries that tenant. |

The keys use the same format the module uses everywhere else. `iss` is the
token issuer. `sub` is the person. `actor` is the agent: the token's
top-level `act.sub`, or `azp` when there is no `act.sub`.

The module checks the registry on every governed call, before the tool
runs. It checks again just before a governed write is saved. If the
principal is stopped at that point, the write is rolled back. A config
save is reverted the same way.

Queue workers and Drush jobs that carry a stopped principal are refused too.

### What the agent sees

A stopped agent gets the same refusal as a caller with no verified
principal. The message is `A verified principal context is required.`
The agent cannot tell that it was stopped. The reason is recorded only in
the audit log, on a `denied_access` row with the reason `principal_killed`.

### What a stop does not do

- A stop does not revoke tokens at your token issuer.
- A stop does not block the agent from signing in again at the issuer.
  It blocks the agent at this site only.
- A stop does not cancel webhook deliveries that were already queued.
  See [Known limits](#known-limits).
- Token lifetimes are set by your token issuer, not by this module.

## Before you rely on it

1. Run database updates before the site serves traffic:
   `drush updb -y`. Update 10030 creates the registry table. Update
   10034 adds the Drupal uid column on operator bindings.
2. Until the registry table exists, every governed call is refused. The
   module fails closed when it cannot read the registry.
3. Pin Paladin introspection in `settings.php`. See
   [Operator identity](#operator-identity) and `INSTALL.md`. Missing
   pins fail closed.
4. Bind each operator token to a Drupal account that holds
   `administer agent kill switch`. See
   [Bind a token](#bind-a-token).
5. Make sure cron runs. Cron writes the expiry of stops and of
   confirmation windows. The access check does not wait for cron: a stop
   past its end time no longer blocks, even before cron runs.
6. Rehearse every command on a test site before you need it.

## Permissions

All kill switch commands need the permission
`administer agent kill switch`. It is a restricted permission. Grant it
only to operator roles.

Drush 13 starts commands as the anonymous account. The commands do not
use `drush --user` / `--uid` as identity. They read `--operator`, look
up the Drupal account bound to the Paladin token, switch to that
account for the permission check, and switch back. Anonymous is
refused. A mapped account without the permission is refused.

## Operator identity

Every kill-switch Drush command needs both of these:

1. A Paladin access token on `PALADIN_TOKEN` or stdin. Do not pass
   `--token` (it lands in shell history and `ps`).
2. `--operator=<Drupal account name>` for the Drupal account bound to
   that token.

The command introspects the token at Paladin over HTTPS with client
authentication. The response must be `active`, carry a numeric future
`exp`, match the issuer and audience pinned in `settings.php`, and
carry the pinned operator audience or role (for example
`mcp-sentinel-operator`). A token with an `act` or `actor` claim is
refused: agent tokens cannot run the kill switch. If Paladin is
unreachable, the command refuses.

Identity is `paladin:iss|sub` from that response. The token is mapped
to a Drupal account through `mcp_sentinel_operator_binding`.
`--operator` must be that account, or the command exits
`operator_mismatch`.

The two-operator rule is two distinct Paladin identities **and** two
distinct mapped Drupal accounts. The same `iss|sub`, or two tokens
mapped to the same Drupal uid, cannot confirm. Empty, unmapped, or
unverified identities are refused. Binding a second identity onto an
already-bound record is refused.

The OS-user HMAC is off unless `settings.php` sets
`$settings['mcp_sentinel.allow_drush_os_assertion'] = TRUE`. Config
cannot turn that on. Even then, euid 0 and the web-server user
(`www-data` / the `mcp_sentinel.web_server_user` pin) are refused.
The process user and `SUDO_USER` are written to the audit row as
advisory metadata only. They are not the operator identity.

The module cannot tell when one person holds two separate accounts at
the token issuer that map to two Drupal accounts. It treats them as
two operators.

Keep agent credentials off the Drush shell.

### Bind a token

Bind the token to a Drupal account once:

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-bind --operator=alice
```

Or pipe the token:

```bash
drush mcp-sentinel:operator-bind --operator=alice < token.txt
```

- The command reads the token from `PALADIN_TOKEN` or from standard input.
- It refuses `--token`.
- It checks the token with the issuer's introspection endpoint over HTTPS.
- It takes the person's identity from that response, not from any option.
- `--operator` is the Drupal account this token maps to. If the token is
  already bound, `--operator` must match that account.
- If the issuer cannot be reached, the command fails.
- Binding a second identity onto an already-bound record is refused.
- Removing a binding (`drush mcp-sentinel:operator-unbind`) needs two
  distinct operators. Same token and `--operator` rules.

Set the introspection settings in `settings.php`:

```php
$settings['mcp_sentinel.paladin.introspection_url'] = 'https://idp.example/realms/agents/protocol/openid-connect/token/introspect';
$settings['mcp_sentinel.paladin.issuer'] = 'https://idp.example/realms/agents';
$settings['mcp_sentinel.paladin.audience'] = 'mcp-sentinel-operator-bind';
$settings['mcp_sentinel.paladin.operator_audience'] = 'mcp-sentinel-operator';
$settings['mcp_sentinel.paladin.client_id'] = 'mcp-sentinel-introspect';
$settings['mcp_sentinel.paladin.client_secret'] = 'the-introspection-client-secret';
```

They are not importable config. Run database updates 10031 to 10034.

## Configuration

Three settings in `mcp_sentinel.settings` control the kill switch. They
are not on the settings form. Set them with Drush or with config import.

| Setting | Default | Allowed values | Meaning |
| --- | --- | --- | --- |
| `kill_switch_default_ttl` | `86400` (24 hours) | 1 to 604800 | How long a stop lasts when the operator does not pass `--ttl`. |
| `kill_switch_max_ttl` | `604800` (7 days) | 1 to 604800 | The longest stop allowed. You can lower it. You cannot raise it above 7 days. |
| `kill_switch_confirm_window` | `900` (15 minutes) | 1 or more | How long the second operator has to confirm. |

```bash
drush config:set mcp_sentinel.settings kill_switch_default_ttl 43200
```

A value above 7 days is an error. The module does not clamp it. If
either TTL setting is above 7 days, every stop fails with
`Kill-block TTL cannot exceed 7 days.`

A requested `--ttl` above the maximum is also an error.

## The two-operator rule

A stop of one agent takes effect at once. One operator is enough.

These requests need a second operator:

- a stop of more than one agent in one command
- any person-wide stop
- any tenant-wide stop
- every lift (un-kill), including a lift of one agent

The second operator must present a different Paladin `iss|sub` **and**
a different mapped Drupal account. The same identity confirming its
own request is refused. Two tokens mapped to one Drupal uid are
refused. A confirmation without a verified, mapped identity is
refused.

There is no fallback when the second operator is unavailable. There is
no timeout that turns a request into a one-operator action. There is no
skip.

## Stop one agent

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --principal-key='ISS|SUB|ACTOR' --reason='Short reason'
```

Quote the key. The `|` character is special in most shells.

The reason is required. It must not contain a token. A reason that starts
with `eyJ`, or contains `Bearer` followed by a space, is refused.

Add `--ttl=SECONDS` to set a lifetime other than the default.

The command prints:

```text
status: killed
batch: <batch id>
block_until: <Unix time>
ttl: <seconds>
```

The stop is in force from that moment. The next governed call from that
agent is refused.

## Stop every agent of one person, or a tenant

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --human-key='ISS|SUB' --reason='Short reason'
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill --operator=alice --tenant='TENANT' --reason='Short reason'
```

You can repeat `--principal-key`, `--human-key`, and `--tenant` in one
command. Any command with more than one target needs a second operator.

The command prints:

```text
status: kill_pending
batch: <batch id>
needs_confirm: yes (named second person / secondary account holder)
ttl: <seconds>
```

**A pending stop is not in force.** The agents in scope keep working
until a second operator confirms. Give the batch id to the second
operator at once.

If every target is already stopped, no confirmation is needed. The
command prints `status: killed` and an empty batch id.

### Confirm a pending stop

The second operator runs with their own Paladin token and `--operator`:

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-confirm BATCH_ID --operator=bob
```

The command prints `status: killed`, the batch id, `block_until`, and the
TTL. The stop is in force from that moment.

The stop's end time is counted from the first operator's request, not
from the confirmation.

### When the confirmation window runs out

After the window ends, `kill-confirm` fails with
`The confirm window has elapsed.`

On the next cron run, the pending rows change to `expired`. The audit log
gets an `agent_kill_expire` row with the reason `confirm_window`. The
module also calls `hook_mcp_sentinel_kill_unavailable_confirmer`.

The stop never took effect. To stop those agents, start a new request.

## Extend a stop

Run `mcp-sentinel:kill` again on a stopped target. The target stays
stopped. The end time can move later, up to 7 days from now. It never
moves earlier.

A new request never turns a stopped target back into a pending one. This
holds for person-wide and tenant-wide requests too. When every target is
already stopped, the extension takes effect without a second operator.

## Lift a stop (un-kill)

Every lift needs two operators.

The first operator requests the lift:

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:unkill --operator=alice --principal-key='ISS|SUB|ACTOR' --reason='Short reason'
```

Use `--human-key` or `--tenant` for those kinds of stop. The command
prints `status: unkill_pending` and a batch id.

**The target stays stopped while the lift is pending.**

The second operator confirms with their own token and `--operator`:

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:unkill --operator=bob --confirm-batch=BATCH_ID
```

The command prints `status: expired`. The target can act again from that
moment.

If the window runs out first, the confirmation fails with
`The confirm window has elapsed.` On the next cron run, the row goes back
to `killed`. The target stays stopped until its end time.

A new stop on a target with a pending lift cancels the lift.

You cannot lift a stop that has already ended. The request fails with
`That kill-block has already expired.`

## Check a stop

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-status --operator=alice --principal-key='ISS|SUB|ACTOR'
```

Pass exactly one selector. If there is no row, the command prints
`status: active`. Otherwise it prints a table with `status`,
`selector_type`, `selector_key`, `block_until`, `ttl`, `batch_id`,
`requested_by`, `confirmed_by`, and `unkill_batch_id`.

`block_until` is a Unix timestamp. The `requested_by` and `confirmed_by`
values are operator identity hashes, not names.

The status column is the stored row. Cron writes expiry. A row can still
say `killed` after its `block_until` has passed. Compare `block_until`
with the current time to know whether the stop still blocks.

Check one target at a time. A person-wide stop is stored under the person's
key (`iss|sub`), so check it with `--human-key`, not with each agent's key.

### Confirm that a stop works

1. Run `kill-status` and confirm `status: killed` and a future
   `block_until`.
2. Open the audit log at `/admin/reports/mcp-sentinel/audit` and filter
   by operation `agent_kill`. Confirmations are `agent_kill_confirm`.
3. After the agent's next call, filter by operation `denied_access`. A
   row with the reason `principal_killed` shows the refusal.

The audit log page needs the `view mcp sentinel audit log` permission. It
shows up to 200 recent rows.

## Audit records

Every transition writes an audit row. These rows are written even when
`audit_enabled` is off.

| Operation | When |
| --- | --- |
| `agent_kill` | A stop request, in force or pending. |
| `agent_kill_confirm` | A second operator confirmed a stop. |
| `agent_kill_expire` | A stop ended (`ttl`), a stop window ran out (`confirm_window`), or a lift window ran out (`unkill_confirm_window`). |
| `agent_unkill_request` | A lift was requested. |
| `agent_unkill` | A second operator confirmed a lift. |

Each row records the operator identity hash, the targets, the reason,
the TTL, the end time, and the batch id. Tokens are never recorded. The
OS user and `SUDO_USER` may appear as advisory metadata only.

## Hooks and events

When a confirmation window runs out, the module calls
`hook_mcp_sentinel_kill_unavailable_confirmer()`. The module's own
implementation dispatches `McpKillUnavailableConfirmerEvent`.

Use these to notify people. An implementation must not apply a pending
stop or complete a pending lift. See `mcp_sentinel.api.php`.

## Known limits

- There is no admin UI for stops. There is no stop route over `/mcp`.
  Drush is the only operator surface.
- A pending person-wide or tenant-wide stop is not in force until a
  second operator confirms.
- Webhook deliveries already in `mcp_sentinel_webhook_delivery` still
  go out after a stop. This release does not cancel them, delete the
  queue, or fail rows on the webhook admin page. Holding those
  deliveries is DEV-985. New admits and in-flight governed writes are
  refused.
- A stop does not revoke tokens at your issuer.
- A stop lasts at most 7 days. Extend it before it ends if you need
  longer.

## Planned (DEV-985)

**None of this is in a release. Do not rely on it.** It is planned work,
tracked as DEV-985. Details may change before it ships.

- **Freeze first.** A person-wide or tenant-wide stop would take effect
  at once, as a freeze, when the first operator issues it. The second
  operator would then keep, extend, or lift the freeze.
- **Fail safe when nobody confirms.** The proposed default is that an
  unconfirmed freeze stays in place when the window ends. It would
  escalate instead of lifting on its own. Lifting it would take two
  operators.
- **Hold queued webhooks.** On any stop, queued webhook deliveries and
  other queued side effects for the stopped scope would be held. An
  operator would release or discard each one. Lifting a stop would not
  release them.

Until this ships, use the behavior described above.
