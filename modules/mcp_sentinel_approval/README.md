# MCP Sentinel Approval

An optional **human-in-the-loop gate** for MCP Sentinel. When enabled, a
governed *destructive* operation is not executed immediately — it is queued as
an approval request for an authorized human to approve or deny. On approval the
stored operation is replayed; on denial it is discarded.

See its help at `/admin/help/mcp_sentinel_approval` and the project
[`README.md`](../../README.md).

## What it gates

- The operations you select on the **approval settings** form — by default bulk
  `delete`, `config_import` (config set/import), and `module_disable`.
- Privilege escalation (`grant_mcp_admin`) is **always** gated, regardless of
  settings. `drush mcp-sentinel:break-glass <uid>` raises an approval request;
  on approval the user receives a **time-boxed** `mcp_admin` role that a cron
  reaper auto-revokes at the configured TTL.

## Break-glass role (`mcp_admin`)

Enterprise posture: least privilege and separation of duties.

- **Who:** a human operator in an emergency — not an agent. An agent cannot
  request break-glass over the MCP channel; widening an agent stays a **policy
  profile** change (reviewable config), not this role.
- **What it is:** a non-`is_admin` role with an explicit permission set. The
  module ships it as optional config (`config/optional/user.role.mcp_admin.yml`)
  when the role does not already exist.
- **Shipped permissions** (`McpBreakGlassManager::ALLOWED_PERMISSIONS` — keep
  identical to `config/optional/user.role.mcp_admin.yml`):
  - `access administration pages`
  - `view the administration theme`
  - `access site reports`
  - `view mcp sentinel audit log`
  - `administer mcp sentinel`
- **Not on this role:** `approve mcp sentinel operations` (a standing second
  person holds approve — so break-glass cannot rubber-stamp the next elevation),
  nor escape-hatch permissions (`bypass node access`, `administer users`, etc.),
  nor `administer site configuration` / `administer modules` (shell or a
  deliberate separate grant).
- **Fail closed (grant-time allowlist):** grants refuse when the role is
  missing, flagged `is_admin`, or holds **any** permission outside the
  allowlist. A proper subset of the allowlist still grants (narrower is safer).
- **Sealed, single-use, not for superusers:** each grant is HMAC-sealed
  with the audit-chain signing key and the idempotency key is consumed
  once. Uid 1 and any account that already holds an `is_admin` role
  cannot receive the role. A missing signing key refuses the grant.
- **Cannot promote policy or lift the publish floor:** while a grant is
  live the holder cannot save or delete a policy profile and cannot
  turn `deny_publish` off. Those refusals are audited as
  `break_glass_refused`.
- **Configuration vs use:** changing `mcp_sentinel_approval.settings`
  is audited as `break_glass_configured`. Other config saves while
  elevated stay `config_save_break_glass`.
- **Empty / narrow role edge:** if every shipped permission is stripped, the
  empty set is still a subset of the allowlist, so **grant succeeds** and the
  Status report only WARNINGs the missing shell permissions. That is
  intentional (narrower is safer) but the elevated user gets nothing useful —
  not a grant failure. Restore the shipped set from the optional YAML (or the
  constant) if break-glass should be an operator shell again.
- **Status report:** ERROR for missing role, `is_admin`, or allowlist extras;
  WARNING when the role is missing one or more shipped permissions (incomplete
  operator shell).
- **Live-grant revalidation:** on cron, if `mcp_admin` is missing, `is_admin`,
  or holds allowlist extras while grants are still active, those grants are
  force-revoked (role removed, audit `mcp_admin_revoked` with reason
  `role_posture_unsafe`). Narrower-than-allowlist alone does not force-revoke.
- **Conduct audit while elevated:** config saves made by a user with a live
  grant are audited as `config_save_break_glass` (config name, changed **key
  names** only — never values — grant id, acting uid), including when the
  holder sets `audit_enabled: false`. Ordinary admins without a live grant are
  unchanged. If the audit write fails, the config save is refused (fail closed).
- **People → Roles warning:** editing `mcp_admin` shows a Sentinel warning with
  the allowlist and points at the Status report.

### Dual-edit rule (YAML ≡ constant)

`McpBreakGlassManager::ALLOWED_PERMISSIONS` and
`config/optional/user.role.mcp_admin.yml` **must stay identical**. Edit both in
the same commit. The kernel test
`McpBreakGlassTest::testOptionalConfigYamlShipsApprovedList` blocks drift in
the normal Tests workflow — do not change only one side.

Enforcement uses a veto seam in the base module: a gated operation dispatches a
destructive-operation event that this submodule vetoes to hold the operation.
If the submodule is not enabled, nothing vetoes and operations run subject only
to the policy-profile gates.

## Admin surfaces

| Page | Path |
|------|------|
| Approvals queue (approve / deny) | `/admin/reports/mcp-sentinel/approvals` |
| Break-glass grants (who holds it, until when) | `/admin/reports/mcp-sentinel/grants` |
| Approval settings (gated operations + TTL) | `/admin/config/services/mcp-sentinel/approval` |

The approvals and grants pages are also local-task tabs on the governance
dashboard. Access to the queue and grants requires the **Approve MCP Sentinel
operations** permission; the settings form requires **Administer MCP Sentinel
settings**.

## Requirements

- `mcp_sentinel` (parent)
