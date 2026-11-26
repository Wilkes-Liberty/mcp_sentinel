---
section: Changed
---
Governed `/mcp` reads now write an audit row that carries the
Paladin-verified `iss|sub|actor` key and the token-derived
tenant from the frozen principal context, never from tool
arguments or request input. A missing principal or network
tenant refuses the read and is audited. `audit_log_reads` still
gates allow rows. JSON:API, GraphQL, Drush, and Context reads
are unchanged. No `updatedb`. No VERSION bump.
