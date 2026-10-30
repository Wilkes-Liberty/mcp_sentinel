---
section: Fixed
---
A principal-context `denied_access` write that still fails after
the 3.6.0 identity bound (chain down, disk full) is logged at
`critical` with the stable event id `denied_access_write_failed`.
The caller stays denied; an unaudited denial is never an allow.
`boundChainIdentity()` hashes a non-scalar `id` / `entity_type` /
`bundle` instead of casting it to `Array` or throwing, uses named
constants for the audit_chain_log 128/128/255 column widths, and
stores the digest only as `sha256:<hex>` (no duplicate
`id_sha256`). A dispatcher admit of a 771-character delegated key
still writes exactly one `denied_access` row when `entity_id` is
enforced at 255 bytes (MySQL, PostgreSQL, and a SQLite trigger
that matches strict mode). Follow-up to DEV-1180 / #396. No
`updatedb`.
