---
section: Changed
---
Webhook event names are a hard allowlist (`mcp.entity.presave`, `mcp.entity.delete`, `mcp.anomaly.alert`). Unknown names are refused on settings save and are never dispatched. A stored `mcp.entity.save` filter is still shown as stored and still needs the live name before anything else can be saved.
