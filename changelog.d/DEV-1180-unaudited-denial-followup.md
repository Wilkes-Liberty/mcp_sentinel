---
section: Fixed
---
A principal-context `denied_access` write that still fails after
the 3.6.0 identity bound (chain down, disk full) is logged at
`critical` with the stable event id `denied_access_write_failed`.
The line names a bounded or hashed tool id and principal key.
Only the exception class is logged, never the raw message (it
can contain SQL fragments). The caller stays denied; an
unaudited denial is never an allow. `boundChainIdentity()`
hashes a non-scalar `id` / `entity_type` / `bundle` instead of
casting it to `Array` or throwing. Canonical JSON for that hash
goes through `McpCanonicalJson` — the same recursive map-key
sort and list-order rule as `McpPolicyBundle::normalize()` —
after expanding `JsonSerializable` and public object
properties on the identity path only. Policy claims stay
arrays and scalars. An empty identity object encodes as
`{}`; an empty list encodes as `[]`. Recursion is capped
at `McpCanonicalJson::MAX_DEPTH` (512, json_encode's
default) on both paths. `MAX_NODES` and `MAX_BYTES` apply
only on the identity path so a bundle that verified on 1.x
still verifies. A visited-object set, a visit budget
(containers and scalars), and a payload budget sit next to
that depth cap on the identity walk so a cycle, a
shared-reference fan-out, a wide scalar list, or repeated
large strings throw inside the normalizer and become a type
marker instead of a fatal that skips the `denied_access`
row. `McpPolicyBundleRegistry::verify()` catches those
throws and returns NULL so `simulate()` records
`bundle_unverified` and `checkBundleFloor` audits the deny.
A throwing `jsonSerialize()` or a FALSE encode also falls
back to that marker. Named constants cover the
audit_chain_log 128/128/255 column widths; the digest is
stored only as `sha256:<hex>` (no duplicate `id_sha256`). A
dispatcher admit of a 771-character delegated key still writes
exactly one `denied_access` row when `entity_id` is enforced
at 255 bytes (MySQL, PostgreSQL, and a chain decorator that
matches strict mode on SQLite). Follow-up to DEV-1180 / #396.
No `updatedb`.
