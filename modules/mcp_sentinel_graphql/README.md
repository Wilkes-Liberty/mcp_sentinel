# MCP Sentinel GraphQL

Extends MCP Sentinel governance to a [GraphQL Compose](https://www.drupal.org/project/graphql_compose)
endpoint.

This submodule has **no settings of its own** — it reads the same policy
profiles and Data Loss Prevention settings as the base module. See its help at
`/admin/help/mcp_sentinel_graphql` and the project [`README.md`](../../README.md).

## What it does

For a governed MCP agent, it applies the resolved policy profile to GraphQL
Compose responses:

- **Field-name redaction** — fields in the profile's `redacted_fields` list are
  replaced with `[REDACTED]`.
- **DLP value-pattern masking** — string values are scanned for configured PII
  patterns (opt-in via the DLP settings).
- **Exfiltration result caps** — multi-value field lists are truncated to the
  profile's `result_count_cap`.
- **Mutation gating and audit** — governed mutations are gated and audited.

Entity allow/deny is handled by the base module's `hook_entity_access`. Governed
and non-governed responses are cached separately (the `user.roles` and
`oauth2_scopes` cache contexts are added).

## Requirements

- `mcp_sentinel` (parent)
- `graphql_compose`

## Usage

Enable the submodule — no further configuration is required. Set redacted
fields and gates per policy profile, and enable DLP, from the **MCP Sentinel
settings** and profile forms in the base module.
