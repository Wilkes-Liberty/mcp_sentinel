---
section: Changed
---
Webhook event names are a hard allowlist (`mcp.entity.presave`, `mcp.entity.delete`, `mcp.anomaly.alert`). Unknown names are refused on settings save. `McpEventDispatcher::dispatch()` and `enqueueForEvent()` now drop unknown names: third-party callers of the `mcp_sentinel.event_dispatcher` service get a refused no-op that is audited. `dispatch()` accepts entity events only. The worker, requeue, and replay paths refuse a stored unknown `event_name` the same way. A stored `mcp.entity.save` filter is still shown as stored and still needs the live name before anything else can be saved.
