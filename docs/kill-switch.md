# Agent kill switch

The kill switch lets an operator stop an agent from acting on your site.
This page explains what it does, how to set it up, and how to issue,
confirm, check, and lift a stop.

The kill switch shipped in release 3.2.0. Freeze-first mass stops,
held side effects, and break-glass (DEV-985) are on the `1.x`
branch and listed under Unreleased in `CHANGELOG.md`. They are not
in 3.2.0.

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

## Before you rely on it

1. Run database updates before the site serves traffic:
   `drush updb -y`. Update 10030 creates the registry table. Update
   10034 adds hold-queue columns and the escalation stamp.
2. Until the registry table exists, every governed call is refused.
   The module fails closed when it cannot read the registry.
3. Make sure cron runs. Cron writes kill-block expiry (the 24 hour /
   7 day stop lifetime) and escalates an unconfirmed freeze when the
   confirm window ends. Cron does not lift that freeze. A stop past
   its `block_until` no longer blocks, even before cron runs.
4. Give each operator an individual OS account on the machine where
   Drush runs. See [Operator identity](#operator-identity).
5. Rehearse every command on a test site before you need it.

## Permissions

All kill switch commands need the permission
`administer agent kill switch`. It is a restricted permission. Grant it
only to operator roles.

The commands check this permission against the Drupal account Drush is
running as. They refuse the anonymous account with the message
`An operator account is required.` Drush 13 starts commands as the
anonymous account. Check on a test site how your Drush setup runs these
commands as a permitted account.

The Drupal account is used only for this permission check. It is not the
identity used for the two-operator rule.

## Operator identity

The two-operator rule needs to tell operators apart. It does not use the
Drupal account for this, because anyone with a shell could switch Drupal
accounts.

On the Drush path, the operator identity is a keyed hash of the OS user
id that runs the PHP process. The key is the site's private key. The
login name and the `USER` environment variable do not change it.

This has three consequences:

- Each operator needs their own OS account.
- A shared deploy account counts as one operator.
- If every operator runs Drush through a wrapper that switches to the
  same OS user, every operator looks like the same person. The second
  operator's confirmation is then refused.

The Drush shell sits outside the module's governance. Keep agent
credentials off that shell.

The module cannot tell when one person holds two separate accounts at
the token issuer. It treats them as two operators.

### Binding an issuer identity to a Drush identity (newer than 3.2.0)

This subsection describes code on the `1.x` branch that is listed under
Unreleased in `CHANGELOG.md`. It is not in 3.2.0.

An operator can link their issuer identity and their Drush identity to
one operator record. After that, the same person cannot request on one
channel and confirm on the other. A confirmation that mixes channels
without a binding is refused.

The module's settings and commands call the token issuer "Paladin".

```bash
PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-bind
drush mcp-sentinel:operator-bind < token.txt
```

- The command reads the token from `PALADIN_TOKEN` or from standard input.
- It refuses `--token`, because a token on the command line lands in
  shell history.
- It checks the token with the issuer's introspection endpoint over HTTPS.
- It takes the person's identity from that response, not from any option.
- If the issuer cannot be reached, the command fails.
- Removing a binding (`drush mcp-sentinel:operator-unbind`) needs two
  distinct operators.

Set the introspection settings in `settings.php`, as shown in
`INSTALL.md`. They are not importable config. Run database updates
10031 to 10033 first.

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

The second operator must have a different operator identity from the
first. The same identity confirming its own request is refused. A
confirmation without a verified identity is refused.

There is no timeout that turns a mass stop into a one-operator action.
The freeze stays until a distinct second operator keeps, extends, or
lifts it. When the named second person cannot be reached, use
[Break-glass](#break-glass). That still needs a distinct verified
operator. It is not a skip of the two-operator rule.

## Stop one agent

```bash
drush mcp-sentinel:kill --principal-key='ISS|SUB|ACTOR' --reason='Short reason'
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
drush mcp-sentinel:kill --human-key='ISS|SUB' --reason='Short reason'
drush mcp-sentinel:kill --tenant='TENANT' --reason='Short reason'
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

**A mass stop freezes immediately.** `kill_pending` is an active freeze.
In-scope agents are refused from that moment, the same as a single-agent
stop. Give the batch id to the second operator at once.

If every target is already stopped, no confirmation is needed. The
command prints `status: killed` and an empty batch id.

### Confirm, extend, or lift the freeze

The second operator runs, from their own OS account:

```bash
drush mcp-sentinel:kill-confirm BATCH_ID
drush mcp-sentinel:kill-extend BATCH_ID --ttl=604800
drush mcp-sentinel:kill-lift BATCH_ID
```

`kill-confirm` keeps the freeze and records the second operator. The
agents were already refused. The stop's end time is counted from the
first operator's request, not from the confirmation.

`kill-extend` moves the end time later, up to 7 days from now. A
requested lifetime above 7 days is refused.

`kill-lift` ends an unconfirmed freeze. Held deliveries stay held.
Lifting a mass freeze always takes two operators. The requester cannot
lift their own stop.

The requesting operator cannot confirm their own stop.

### When the confirmation window runs out

The freeze stays in place. It never lifts on that timeout. On the next
cron run the audit log gets an `agent_kill_escalate` row. The module
calls `hook_mcp_sentinel_kill_unavailable_confirmer` so you can notify
the named second person and the break-glass path.

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
drush mcp-sentinel:unkill --principal-key='ISS|SUB|ACTOR' --reason='Short reason'
```

Use `--human-key` or `--tenant` for those kinds of stop. The command
prints `status: unkill_pending` and a batch id.

**The target stays stopped while the lift is pending.**

The second operator confirms from their own OS account:

```bash
drush mcp-sentinel:unkill --confirm-batch=BATCH_ID
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
drush mcp-sentinel:kill-break-glass BATCH --keep
drush mcp-sentinel:kill-break-glass BATCH --extend --ttl=604800
drush mcp-sentinel:kill-break-glass BATCH --lift
```

The pinned break-glass operator is Aleksandra Cerda (`acerda`). The
command still requires a distinct verified operator. The requester
cannot break-glass their own stop. The audit row is
`agent_kill_break_glass`, not a confirm / extend / lift row.

Rehearse this with `McpKillSwitchBreakGlassDrillTest` alongside the
scheduled kill-switch drill (DEV-855).

## Held webhook deliveries

On any stop (one agent, person-wide, or tenant-wide), webhook
deliveries already queued for that scope move to `held` and are not
sent. Items outside the scope still send. Lifting the stop does not
release them.

Review held rows, then release or discard each one, or a batch:

```bash
drush mcp-sentinel:webhook-held
drush mcp-sentinel:webhook-release --id=12 --id=13
drush mcp-sentinel:webhook-discard --id=12
```

A released item delivers exactly as originally queued: same payload,
same delivery id, same body signature. A discarded item is never sent.
Do not use `drush queue:delete`. Cron does not re-queue held rows.

## Check a stop

```bash
drush mcp-sentinel:kill-status --principal-key='ISS|SUB|ACTOR'
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

1. Run `kill-status`. A mass freeze shows `status: kill_pending` or
   `killed` and a future `block_until`. Agents in scope are refused
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
| `agent_kill_escalate` | The confirm window ended and the freeze stayed. |
| `agent_kill_break_glass` | Break-glass keep, extend, or lift. |
| `agent_kill_expire` | A stop ended (`ttl`) or a lift window ran out (`unkill_confirm_window`). |
| `agent_unkill_request` | A lift of a confirmed stop was requested. |
| `agent_unkill` | A second operator confirmed that lift. |
| `agent_side_effect_hold` | Queued deliveries in scope were held. |
| `agent_side_effect_release` | An operator released held deliveries. |
| `agent_side_effect_discard` | An operator discarded held deliveries. |

Each row records the operator, the scope, the timestamp, and the
correlation or batch / item ids. Tokens are never recorded. Each of
those events writes exactly one row.

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
  each one explicitly.
