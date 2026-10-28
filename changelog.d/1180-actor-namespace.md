---
section: Security
---
Separate the principal-key actor slot so a token's `act.sub` cannot occupy an `azp` identity. Delegated keys store `act:` plus the current actor; non-delegated `iss|sub|azp` keys are unchanged. Tokens whose `azp` equals `act.sub` (or whose `azp` already uses that prefix) fail closed with an audited `actor_claim_collision` denial.
