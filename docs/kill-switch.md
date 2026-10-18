# Agent kill switch

The kill switch lets an operator stop an agent from acting on your site.
This page explains what it does, how to set it up, and how to issue,
confirm, check, and lift a stop.

The kill switch shipped in release 3.2.0. Freeze-first mass stops,
held side effects, and break-glass (DEV-985) and Paladin-token
operator identity (DEV-986) are on the `1.x` branch and listed
under Unreleased in `CHANGELOG.md`. They are not in 3.2.0.

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
- A stop does not release held webhook deliveries. Release is a
  separate operator action. See [Held webhook deliveries](#held-webhook-deliveries).
- Token lifetimes are set by your token issuer, not by this module.
  Pin Paladin operator tokens to 8 hours absolute lifetime and 30
  minutes idle. The kill-block default is 24 hours with a 7 day
  maximum.

## Before you rely on it

1. Run database updates before the site serves traffic:
   `drush updb -y`. Update 10030 creates the registry table. Update
   10034 adds the Drupal uid column on operator bindings. Update
   10036 adds hold-queue columns and the escalation stamp. Update
   10037 resets Paladin uids, drops leftover Drush rows, keeps
   Drush-requested freezes, and requires every operator to re-bind.
   Update 10038 records the pre-upgrade max delivery id, drops
   unused `released`, and holds remaining keyless pending rows
   when a stop is active. Every keyless row stays stopped while
   any stop is active, including rows queued after 10038. Roll
   back 10038 only as documented in `INSTALL.md`.
2. Until the registry table exists, every governed call is refused.
   The module fails closed when it cannot read the registry.
3. Pin Paladin introspection in `settings.php`. See
   [Operator identity](#operator-identity) and `INSTALL.md`. Missing
   pins fail closed.
4. Bind each operator token to a Drupal account that holds
   `administer agent kill switch`. See
   [Bind a token](#bind-a-token).
5. Make sure cron runs. Cron writes kill-block expiry for confirmed
   stops (the 24 hour / 7 day lifetime) and escalates an unconfirmed
   freeze when the confirm window ends. Cron does not lift that
   freeze. An unconfirmed freeze stays frozen after `block_until`
   until two operators lift it or break-glass is used. A confirmed
   stop past its `block_until` no longer blocks, even before cron
   runs.
6. Rehearse every command on a test site before you need it.
7. Pin the break-glass operator in `settings.php` as a Paladin
   `iss|sub`:
   `$settings['mcp_sentinel.kill_switch.break_glass_operator']`.
   A Drupal username or uid pin is refused. Without that pin,
   break-glass is refused.

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
carry the pinned operator audience on `aud` or a role (for example
`mcp-sentinel-operator`). `azp` and `client_id` are not
operator-audience matches. A token with an `act` or `actor` claim is
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

The process user and `SUDO_USER` are written to the audit row as
advisory metadata only. They are not the operator identity. After
update 10037 every kill command, including `kill-extend`,
`kill-lift`, `kill-break-glass`, `webhook-held`, `webhook-release`,
and `webhook-discard`, refuses every operator until they re-bind.
Break-glass is refused until that identity is bound again.

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
- A uid may be bound to only one `iss|sub`.
- The pinned name claim (default `preferred_username`) must match
  `--operator`. A mail-type name claim needs
  `mcp_sentinel.paladin.operator_mail_claim` as well. Name and
  mail comparisons are case-sensitive.
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
$settings['mcp_sentinel.paladin.operator_name_claim'] = 'preferred_username';
// Optional. When set, email_verified must be true and the mail must match.
$settings['mcp_sentinel.paladin.operator_mail_claim'] = 'email';
```

They are not importable config. Run database updates 10031 to 10038.

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
A non-integer, zero, or negative `--ttl` is refused with
`invalid_ttl`.

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

There is no timeout that turns a mass stop into a one-operator action.
The freeze stays until a distinct second operator keeps, extends, or
lifts it. When the named second person cannot be reached, use
[Break-glass](#break-glass). That still needs a distinct verified
operator. It is not a skip of the two-operator rule.

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
needs_confirm: yes (a distinct bound operator).
freeze: in force now. Unconfirmed timeout keeps it and escalates.
block_until: <unix>
ttl: <seconds>
```

**A mass stop freezes immediately.** `kill_pending` is an active freeze.
In-scope agents are refused from that moment, the same as a single-agent
stop. Give the batch id to the second operator at once.

If every target is already stopped, no confirmation is needed. The
command prints `status: killed` and an empty batch id.

### Confirm, extend, or lift the freeze

The second operator runs with their own Paladin token and `--operator`:

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-confirm BATCH_ID --operator=bob
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-extend BATCH_ID --operator=bob --ttl=604800
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-lift BATCH_ID --operator=bob
```

`kill-confirm` keeps the freeze and records the second operator. The
agents were already refused. Confirm also refreshes `block_until` to
`min(now+7d, max(existing, now+ttl))` so an overdue freeze does not
lift the moment it is confirmed.

`kill-extend` moves the end time later, up to 7 days from now. A
requested lifetime above 7 days is refused.

`kill-lift` ends an unconfirmed freeze. Held deliveries stay held.
Lifting a mass freeze always takes two operators. The requester cannot
lift their own stop.

The requesting operator cannot confirm their own stop.

### When the confirmation window runs out

The freeze stays in place. It never lifts on that timeout. An
unconfirmed freeze also stays frozen after its TTL (`block_until`)
until two operators lift it or break-glass is used. Confirmed stops
still expire at their TTL. On the next cron run the audit log gets an
`agent_kill_escalate` row (reason `confirm_window`) after the
batch is claimed. The module then calls
`hook_mcp_sentinel_kill_unavailable_confirmer` so you can notify
the named second person and the break-glass path. A hook throw
writes a second escalate row with reason `notify_failed` and
does not lift the freeze. Un-kill window expiry writes
`agent_kill_expire` first, then notifies.

A distinct second operator can still confirm, extend, or lift after the
window, or use [Break-glass](#break-glass) when that person cannot be
reached.

## Extend a confirmed stop

Run `mcp-sentinel:kill` again on a stopped target, or
`mcp-sentinel:kill-extend` on a freeze batch. The target stays
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
moment. Held deliveries stay held. Lifting a stop never releases them.

If the window runs out first, the confirmation fails with
`The confirm window has elapsed.` On the next cron run, the row goes back
to `killed`. The target stays stopped until its end time.

A new stop on a target with a pending lift cancels the lift.

You cannot lift a stop that has already ended. The request fails with
`That kill-block has already expired.`

## Break-glass

Use this when the named second person cannot be reached and the freeze
must be kept, extended, or lifted.

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-break-glass BATCH --operator=breakglass-op --keep
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-break-glass BATCH --operator=breakglass-op --extend --ttl=604800
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:kill-break-glass BATCH --operator=breakglass-op --lift
```

The break-glass operator is configured in `settings.php` as a Paladin
`iss|sub`
(`$settings['mcp_sentinel.kill_switch.break_glass_operator']`). A
Drupal username or uid pin is refused. Only that Paladin identity
can use this path. Everyone else is refused. The requester cannot
break-glass their own stop. The audit row is
`agent_kill_break_glass`, not a confirm / extend / lift row.

Rehearse this with `McpKillSwitchFreezeHoldTest` alongside the
scheduled kill-switch drill (DEV-855).

## Held webhook deliveries

On any stop (one agent, person-wide, or tenant-wide), webhook
deliveries already queued for that scope move to `held` and are not
sent. Items outside the scope still send. Lifting the stop does not
release them.

Review held rows, then release or discard each one, or a batch:

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:webhook-held --operator=alice
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:webhook-release --operator=alice --id=12 --id=13
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:webhook-discard --operator=alice --id=12
```

A released item delivers exactly as originally queued: same payload,
same delivery id, and the same `X-MCP-Signature`. `X-MCP-Timestamp`
and `X-MCP-Signature-256` are new on each attempt. A discarded item
is never sent. Release is refused while the scope is still stopped:
lift or unkill first. Do not use `drush queue:delete`. Cron does not
re-queue held rows.

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

The status column is the stored row. Cron writes expiry for confirmed
stops. `kill_pending` is always blocking: do not compare
`block_until` to decide whether an unconfirmed freeze is in force.
A `killed` or `unkill_pending` row blocks only while `block_until`
is in the future.

Check one target at a time. A person-wide stop is stored under the person's
key (`iss|sub`), so check it with `--human-key`, not with each agent's key.

### Confirm that a stop works

1. Run `kill-status`. A mass freeze shows `status: kill_pending`
   (always in force, even when `block_until` is in the past) or
   `killed` with a future `block_until`. Agents in scope are refused
   in either state.
2. Open the audit log at `/admin/reports/mcp-sentinel/audit` and filter
   by operation `agent_kill` or `agent_kill_freeze`. Confirmations are
   `agent_kill_confirm`.
3. After the agent's next call, filter by operation `denied_access`. A
   row with the reason `principal_killed` shows the refusal.

The audit log page needs the `view mcp sentinel audit log` permission. It
shows up to 200 recent rows.

## Audit records

Every transition writes an audit row. These rows are written even when
`audit_enabled` is off.

| Operation | When |
| --- | --- |
| `agent_kill` | A single-agent stop. |
| `agent_kill_freeze` | A person-wide or tenant-wide freeze. |
| `agent_kill_confirm` | A second operator kept a freeze. |
| `agent_kill_extend` | A second operator extended a freeze. |
| `agent_kill_lift` | A second operator lifted an unconfirmed freeze. |
| `agent_kill_escalate` | The confirm window ended and the freeze stayed (`confirm_window`), or the confirmer hook threw (`notify_failed`). |
| `agent_kill_break_glass` | Break-glass keep, extend, or lift. |
| `agent_kill_expire` | A stop ended (`ttl`) or a lift window ran out (`unkill_confirm_window`). |
| `agent_unkill_request` | A lift of a confirmed stop was requested. |
| `agent_unkill` | A second operator confirmed that lift. |
| `agent_side_effect_hold` | Queued deliveries in scope were held. |
| `agent_side_effect_release` | An operator released held deliveries. |
| `agent_side_effect_discard` | An operator discarded held deliveries. |
| `agent_kill_refuse` | An operator action was refused. |
| `agent_side_effect_refuse` | A hold, release, discard, or oversized enqueue was refused. |
| `operator_command_refused` | A Drush command refused before a service audit (missing token, token too large, `--token`). |
| `operator_binding_uid_reset` | Update 10037 reset a Paladin uid. Metadata has `previous_uid` and `identity_hash`. |
| `operator_binding_cleared` | Update 10037 deleted a leftover Drush binding row. |
| `operator_binding_upgrade_pending_kept` | Update 10037 kept a Drush-requested freeze. |

Each row records the operator, the scope, the timestamp, and the
correlation or batch / item ids. Tokens are never recorded. A
successful transition writes one row. Refusals write
`agent_kill_refuse` or `agent_side_effect_refuse`. A confirmer hook
that throws writes a second `agent_kill_escalate` row with reason
`notify_failed`. The OS user and `SUDO_USER` may appear as advisory
metadata only.

## Hooks and events

When a confirmation window runs out, the freeze stays and the module
calls `hook_mcp_sentinel_kill_unavailable_confirmer()`. The module's
own implementation dispatches `McpKillUnavailableConfirmerEvent`.

Use these to notify the named second person and the break-glass path.
An implementation must not lift the freeze or complete a pending lift.
See `mcp_sentinel.api.php`.

## Known limits

- There is no admin UI for stops. There is no stop route over `/mcp`.
  Drush is the only operator surface. Drupal-side kill-block records
  are DEV-925.
- A stop does not revoke tokens at your issuer.
- A stop lasts at most 7 days. Extend it before it ends if you need
  longer.
- Lifting a stop never releases held deliveries. Release or discard
  each one explicitly. Release is refused while the scope is still
  stopped.
- An unconfirmed freeze does not expire at `block_until`. It stays
  frozen until two operators lift it or break-glass is used.
- `mcp-sentinel:unkill` is refused on a `kill_pending` row. Use
  `mcp-sentinel:kill-lift`.
- Break-glass is limited to the identity configured in
  `settings.php`. The requester is always refused.
- An in-flight webhook POST cannot be recalled. A retry cannot
  overwrite a held row.
- Rows queued before update 10036 have empty keys. The 10038 hook
  records the pre-upgrade max delivery id and counts remaining
  keyless pending rows. Every keyless row stays stopped while any
  stop is active (release, pre-claim, post-claim, and retry),
  including rows queued after 10038 and rows whose state key is
  missing.
- `kill-extend` never shortens a stop. `block_until` is
  `max(existing, now+ttl)`, capped at now + 7 days.
- The worker re-checks the kill registry after a successful claim.
- Escalation notifies once per batch, not once per row.
