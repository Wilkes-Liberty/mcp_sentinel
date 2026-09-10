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

## Translations

Core JSON:API PATCH of `langcode` does not call `addTranslation()` and is not
used here. Translation writes are explicit:

- `POST .../mcp-draft/translations` creates a target-language translation as a
  new unpublished forward revision. `If-Match` is `"<live>"` when there is no
  working revision, or `"<live>:<working>"` when adding the language onto an
  existing unpublished forward revision. An existing translation on live or
  working is 409, not an overwrite.
- `PATCH .../mcp-draft` with `X-MCP-Draft-Langcode` continues that translation
  only. Omitting the header on a multilingual working revision is 409.
- `GET .../mcp-translations` reports live and (when the principal can view the
  unpublished revision) working languages, titles, publication, and moderation
  state. `GET .../mcp-draft` with the same `If-Match` and language header
  returns that working translation.

The selected translation is the entity that is validated and saved, so
content_moderation sees its unpublished draft state and does not promote the
working revision to the live default. English on the live revision — title,
summary, body, status, alias, and default revision ID — is left unchanged.
Anonymous requests do not receive working-revision languages or the draft
body. Shared aliases, file targets, and paragraph structure cannot be changed
on a translation write.

Paragraph *field values* use the same surface on the paragraph resource:
`POST /jsonapi/paragraph/{bundle}/{uuid}/mcp-draft/translations` with
`If-Match: "<paragraph revision ID>"` and `X-MCP-Draft-Langcode`. That
revision is the one the host already pins. The translation is unpublished.
English default-language paragraph text and live ERR UUID+vid pins stay
unchanged. Nested children are translated the same way; the parent ERR field
is not retargeted. Canonical JSON:API PATCH of a paragraph pinned by a
published host is still redirected or refused (GitHub #46).

Create the node translation first, then read its working revision and follow
that revision's paragraph references. ERR can create new child revisions when
the node creates a forward revision. Do not reuse paragraph revision IDs from
the published node inventory. For nested paragraphs, follow the working
group's child references too; UUIDs stay shared, but revision IDs can differ.

If storage cannot add a translation without a new paragraph revision, that
revision may be pinned only on the unpublished host translation of the same
language. A save that would retarget a live English pin is rolled back.

When paragraph `status` is not translatable (shared across languages on one
revision, as on typical hero/FAQ/CTA bundles), Sentinel does not unpublish
that revision in place. It creates a non-default unpublished revision and
pins it only on the current unpublished host working copy. Live default ERR
UUID+vid pins stay bit-identical. Re-pinning never replays historical host
revision rows.

Image alt is a translatable field on the host when the file target is
unchanged (`translation_sync.file: file`, alt not synced). Replacing the
file on a translation write is refused. Media entity translation is not
enabled by this path.

Creating a translation copies untranslated structure from the source, then
applies only the submitted translatable fields. A published or default-revision
moderation state in the payload is refused. An existing English working copy
keeps its pending English values.

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

This endpoint cannot publish, modify the public alias, or change
non-revisionable fields. Those cases are refused, not silently converted.
Referenced paragraph revisions must already exist; the node endpoint updates
the host references, not child entities in place. Paragraph field values are
translated on the paragraph `/mcp-draft` routes. Translation writes
additionally refuse shared-structure changes (paragraph retargeting, file
replacement). Alt-only image writes are not file replacement.

The JSON:API controller extension uses internal core APIs. Functional coverage
on supported core branches is required before releasing a change to this path.
The draft-continuation functional test also runs on PostgreSQL 16 in GitHub
Actions, including node grants and an existing node-reference field.
