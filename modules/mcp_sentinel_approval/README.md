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
