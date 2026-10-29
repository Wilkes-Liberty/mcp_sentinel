---
section: Docs
---
INSTALL and README Requirements now name the hard `ext-intl` /
`Spoofchecker` (UTS #39) requirement. Without it, governed tool
calls fail closed (`lookalike_check_unavailable`). The webhook
class doc now shows the timestamped `X-MCP-Signature-256` verify
and the README clock-skew check, instead of the body-only HMAC.
