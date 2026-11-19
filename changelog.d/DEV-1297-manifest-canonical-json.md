---
section: Changed
---
Sealed action-manifest claims now go through
`McpCanonicalJson`, the same recursive map-key sort used
for policy-bundle digests and audit-identity hashes.
Empty lists stay `[]`. Over-depth claims (deeper than
`McpCanonicalJson::MAX_DEPTH`, 512) throw
`InvalidArgumentException` instead of reaching
`json_encode`'s depth error. Non-scalar claims still
throw `InvalidArgumentException` with the historical
manifest message. Identity-path node and byte budgets
are unchanged and do not apply to manifests or policy
bundles. Seal bytes for previously valid manifests are
unchanged. No `updatedb`. No VERSION bump.
