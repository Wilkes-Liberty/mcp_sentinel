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
- **Shipped permissions:**
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
- **Fail closed:** if `mcp_admin` is missing or flagged `is_admin`, grants are
  refused and the status report reports ERROR. The module does not silently
  escalate to superuser.

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
