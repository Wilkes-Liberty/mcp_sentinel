---
section: Security
---
Sealed-token reveal is no longer a state-changing GET. After mint,
`GET /admin/config/services/mcp-sentinel/tokens/reveal` is a prompt
and never echoes the secret. Showing the bearer is a POST on that
path and requires Drupal's CSRF token (`_csrf_token`). A missing or
bad token is 403 and reveals nothing; that refusal always writes
`sealed_token_reveal_denied` (`reason` `csrf_invalid`, route, acting
uid — never the bearer or the CSRF token). A valid POST reveals once
and always writes `sealed_token_reveal` (never the bearer), including
when `audit_enabled` is off. Mint and revoke still use `log()` and
honour `audit_enabled`. Operators must use the **Show sealed token**
button instead of relying on a GET of the reveal URL.
