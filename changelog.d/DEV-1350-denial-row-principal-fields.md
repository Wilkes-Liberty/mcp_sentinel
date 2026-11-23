---
section: Changed
---
`denied_access` rows now carry `principal_source`, authorized
party, token id (`jti` only, never the bearer), granted scopes,
and required scopes when known. Claimed but unverified values
use `claimed_*` keys so they cannot be mistaken for a composed
principal. `McpEntityToolTrait::logDeniedAccess()`, the Server
authorization subscriber, and `McpDenyExplainer::refuse()` stamp
the same principal fields. Classification HTTP refuses also
write the content label as `classification` on the HMAC row.
Governed-tool `admit()` pins Paladin `iss` to
`$settings['mcp_sentinel.paladin.issuer']` when that pin is
non-empty; role-fallback and kernel fixture contexts skip the
pin. No `updatedb`. No VERSION bump.
