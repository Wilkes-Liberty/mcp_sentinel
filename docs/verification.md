# Verifying a secure install

A README can claim an install is secure. This verifier produces evidence
for the claim, and fails when the claim is false.

```bash
drush mcp-sentinel:verify
drush mcp-sentinel:verify --live
drush mcp-sentinel:verify --live --content-target=UUID --json > evidence.json
```

The exit code is `0` only when every applicable check ran **and** passed.

Two non-passing outcomes are deliberately different:

- **`skipped`** — the check should have run and could not (no node type, no
  content target, no profile). A skipped check **fails the run**.
- **`n/a`** — the check does not apply to this shape of install (a profile
  that does not grant write has no draft path; a profile that grants
  config write is *supposed* to write config). It does **not** fail the
  run.

Nothing secret reaches the output. The evidence carries versions, a
configuration digest, statuses and audit-row ids — never a token, a
webhook secret, or the body of a governed read.

The operator command **does not create, update or delete content**. Write
gates are decided through the same `validate()`, access checker and
unmoderated-redirect classifier the runtime uses. Each check writes one
`install_verify` audit row and prints its id as evidence. Persist-path
proof (an allowed draft that actually saved; a publish that was
refused) lives in the kernel suite against `config/install`.

## Posture checks (always, no writes)

| Check | What it proves |
|---|---|
| `source_contract` | `McpGovernanceReadiness::contractStatus()` is ready. |
| `companions` | `audit_chain`, `mcp_sentinel_server`, `mcp_server_tool_bridge` and `mcp_server_oauth` are enabled. |
| `keyed_evidence` | Auditing is on and the audit-chain signing key resolves. |
| `finite_budgets` | `require_finite_read_budgets` is on and every profile resolves a finite cap. |
| `active_policy` | An enabled profile binds at least one role. A role-less default is not production policy. |
| `trust_role_separation` | Governed roles are not `is_admin` and hold no forbidden escape-hatch permission. |
| `no_dev_fallback` | `governed_role_fallback` is off. |
| `tenant_neutrality` | Shipped install YAML names no tenant host or inline secret, and active settings name no W&L host. |
| `classification_posture` | A classification vocabulary exists and labels data above the floor. |

## Hostile-input probes (`--live`, still no writes)

| Probe | Attempts | Passes when |
|---|---|---|
| `probe_allowed_draft` | create-access on an unpublished, unsaved node | the profile grants write and create is not forbidden. `n/a` when the profile grants no write. |
| `probe_denied_publication` | `validate()` on an unsaved published node under a process-scoped agent-channel flag | the deny-publish constraint fires. Fails if `deny_publish` is off. |
| `probe_mass_read` | a 5000-item page against the effective result cap | the cap is finite and smaller than 5000. |
| `probe_config_change` | `checkConfigAccess('system.site', 'write')` | the write is forbidden. `n/a` when the profile grants config write. |
| `probe_live_content_edit` | `validate()` and the unmoderated-redirect classifier against `--content-target` | the edit would be refused **or** redirected to a forward revision (the live default stays put). Skipped when no target is supplied. |

A thrown error is not automatically a refusal. The publication probe
passes only on the deny-publish constraint message; a missing bundle or
target is `skipped`.

## Managed residuals

The evidence document ends with residuals on purpose. A verification
that lists only what passed reads as a claim that nothing else is
outstanding.

### Prompt injection — managed, not solved

Prompt injection is **not** solved by this module, and no configuration
of it makes an agent immune. Content read through a governed path can
carry instruction-shaped text, and a model may act on it.

What the stack constrains is the blast radius: least-privilege scopes,
per-role policy, entity and field denies, classification egress
ceilings, finite read budgets, no agent publication authority, and an
audit row for every governed action.

Treat model output as untrusted input to whatever consumes it next.

### Operator trust — managed, not solved

An operator who can run Drush or hold the client secrets can act with
the agent's authority. Secret custody, rotation and revocation stay
with the deploying organisation.

## Evidence for a release proof

`--json` prints the artefact to attach to a release record. It names
the module version, the Drupal version, a `configDigest` of the
verified configuration with secrets redacted, every check outcome, and
the residuals list.
