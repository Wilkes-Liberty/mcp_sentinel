# Governed draft continuation

With JSON:API enabled, Sentinel adds a PATCH endpoint at each mutable node
resource's URL plus `/mcp-draft`. This is separate from core revision reads:
core rejects PATCH requests carrying `resourceVersion`.

The endpoint accepts the ordinary JSON:API `data` document, including attributes
and relationships. Authentication must resolve to a governed principal. The
canonical route's entity access and CSRF requirements are retained, and field
access, validation, content locks, and save-time governance remain active.

Required header: `If-Match: "<live revision ID>:<working revision ID>"`.
Both must match the stored pointers. The working revision must be an unpublished
non-default node revision. A mismatch returns 409; missing or malformed revision
IDs return 400. No automatic retry or revision deletion takes place.

`X-MCP-Draft-Preflight: 1` performs access, field, validation and revision checks
without calling save. Success returns `meta.draft_preflight: true` and the two
checked IDs. The default (`0`) saves a new unpublished continuation and returns
the normal JSON:API resource response. Save-time hooks still run only on the
real write; preflight is not a reservation or a guarantee against later policy
changes, concurrent edits, or save-hook failures.

Validation, including node-reference access queries, runs before the exclusive
write transaction. Preflight never opens a transaction. The write still
row-locks the node, re-checks both revision pointers, and rolls back if the
live revision would change. That transaction scope is required on PostgreSQL:
holding a transaction across nested SELECTs hits core
[#2920527](https://www.drupal.org/project/drupal/issues/2920527)
(`mimic_implicit_commit` already in use). Sites may still want that core
correction for other in-transaction nested SELECTs; this endpoint does not
depend on it.

This endpoint cannot publish, modify the public alias, change non-revisionable
fields, or continue translated nodes. Those cases are refused, not silently
converted. Referenced paragraph revisions must already exist; the endpoint
updates the host references, not child entities in place.

The JSON:API controller extension uses internal core APIs. Functional coverage
on supported core branches is required before releasing a change to this path.
The draft-continuation functional test also runs on PostgreSQL 16 in GitHub
Actions, including node grants and an existing node-reference field.
