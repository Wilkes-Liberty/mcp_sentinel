---
section: Changed
---
The Status report now shows one row when `contract_not_ready` (ERROR) and
`not_governing` (WARNING) name the same gap (`agent_scopes_missing` or
`active_profile_missing`). Both severities stay on that ERROR row so it
cannot sit as warning-only. Distinct gaps remain two rows. What is
reported is unchanged.
