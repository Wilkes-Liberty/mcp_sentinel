---
section: Security
---
A composed principal key over 770 characters is still refused (`part_too_long`), and that denial now always writes `denied_access` on MySQL and MariaDB. The row used to be dropped: `audit_chain_log.entity_id` is `varchar(255)`, a 256-character JWT `sub` (the legal part cap) overflowed it, and the dispatcher swallowed the failed append so the caller still saw 403 with no audit. Unverified denials now stamp `entity_id` `unverified` and keep the full `iss`/`sub` in metadata; every audit write also bounds `id` to 255 and stores the original as `entity_id_unbounded`. No `updatedb`.
