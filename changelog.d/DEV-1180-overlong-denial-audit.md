---
section: Fixed
---
A composed principal key over 770 characters is still refused
(`part_too_long`), but the `denied_access` row is no longer dropped
on MySQL or PostgreSQL. `denialAuditMetadata()` records the 256-
character subject on `id`; audit_chain 1.13.0 copies that onto
`entity_id` varchar(255) without truncating it. MySQL 8 strict mode
and PostgreSQL reject the insert; `deny()` then logs the write
failure and still throws, so the caller is denied with no audit
row (d.o pipeline 1023398, jobs 13226584 and 13226437). The logger
now replaces an oversize `id`, `entity_type`, or `bundle` with a
deterministic `sha256:` digest, keeps the original in metadata, and
writes the row. SQLite still accepts the raw 256-byte value, which
is why GitHub Actions on aa64970 was green. No `updatedb`.
