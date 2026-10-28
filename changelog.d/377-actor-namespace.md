---
section: Security
---
Separate the principal-key actor slot so a token's `act.sub` cannot occupy an `azp` identity. Delegated keys store `act:` plus the current actor; non-delegated `iss|sub|azp` keys are unchanged. An `azp` that already uses that prefix (any case) fails closed with an audited `actor_claim_collision` denial. Kill-switch matching and webhook hold selection treat `iss|sub|X` and `iss|sub|act:X` as aliases of the same stop (fail-closed and over-inclusive: a legacy stop on `iss|sub|X` also stops `azp=X`). No `updatedb`. Rebuild caches (`drush cr`). Operators do not need to re-issue active delegated stops across this deploy. Rolling this change back restores exact-match lookup: re-issue any `act:`-prefixed stops as `iss|sub|<act.sub>` if the previous code is restored.
