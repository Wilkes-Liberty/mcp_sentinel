# Security policy

MCP Sentinel is a governance module — it constrains what AI agents may do on a
Drupal site and records what they did — so please report vulnerabilities
responsibly rather than in a public issue.

## Reporting a vulnerability

- **Email the maintainers privately** (see the project page and
  `MAINTAINERS.txt`) with steps to reproduce. We will acknowledge, assess, and
  coordinate a fix and disclosure.
- Do **not** open a public GitHub or drupal.org issue for an exploitable
  vulnerability.

This project is not yet covered by the Drupal Security Team's advisory process.
Until that coverage is in place, reports go to the maintainers rather than to
[the Security Team form](https://www.drupal.org/security-team/report-issue).
When coverage is added, that process becomes the preferred route for released
versions and this file will be updated.

Please include the affected version, a clear description, and a proof of concept
if you have one.

## Security model and operator responsibilities

MCP Sentinel is only as strong as its deployment. Operators must:

- **Keep signing and encryption secrets out of exported configuration.** Prefer
  Key entities backed by the environment or a file outside the web root. Rotating
  a leaked secret is not optional.
- **Treat governed roles as a boundary, not a convenience.** A role that holds
  `bypass file gate`, `bypass node access`, `administer users`, or similar
  escape hatches makes the policy profile's guarantees untrue. Run
  `drush mcp-sentinel:role-audit` after config import.
- **Keep the agent channel distinct from human admin sessions.** An admin's
  cookie-session UI is not governed; that is intentional. Do not put agent
  credentials on accounts that also operate the site as humans.
- **Understand that audit integrity depends on the signing key and on
  `audit_chain` remaining enabled.** A missing or unresolvable key is reported
  loudly; do not silence that path.

## What the module guarantees

- Policy profiles constrain governed operations through MCP, JSON:API, and
  GraphQL when the request is on the agent channel.
- Fail-closed behaviour when the audit chain is unavailable for a governed
  write (the write is refused rather than performed unaudited).
- Role assertions that report escape-hatch permissions held outside the channel.
- A tamper-evident audit chain when `audit_chain` is configured with a resolvable
  signing key.
