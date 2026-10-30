---
section: Tests
---
`McpSiemStreamingTest` resolves the SIEM channel the way the installed Audit Chain does: `logger.channel.audit_chain` on 1.12.x, `audit_chain.stream` on 1.13.0, and on 1.13.1 and later `audit_chain.stream` only when `stream_exclude_dblog` is set. The 3.6.0 drupal.org pipeline installed Audit Chain 1.13.2 and failed three cases that still expected the 1.13.0 channel. A new case covers the `stream_exclude_dblog` opt-in.
