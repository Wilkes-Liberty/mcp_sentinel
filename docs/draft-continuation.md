# Governed draft continuation

With JSON:API enabled, Sentinel adds a PATCH endpoint at each mutable node
and media resource's URL plus `/mcp-draft`. This is separate from core revision reads:
core rejects PATCH requests carrying `resourceVersion`.

The endpoint accepts the ordinary JSON:API `data` document, including attributes
and relationships. Authentication must resolve to a governed principal. The
canonical route's entity access and CSRF requirements are retained, and field
access, validation, content locks, and save-time governance remain active.

Required header: `If-Match: "<live revision ID>:<working revision ID>"`.
Both must match the stored pointers. The working revision must be an unpublished
non-default node revision. A mismatch returns 409; missing or malformed revision
IDs return 400. No automatic retry or revision deletion takes place.

## Opening the first working copy

When no working copy exists, send `If-Match: "<live revision ID>"`. Sentinel
builds the first unpublished forward revision from a fresh copy of live, in the
default language. Only content-moderated entities can be opened this way. The request must set an unpublished `moderation_state` (for
example `draft`); a published or default-revision state is refused. If a
working copy already exists, or live moved, the response is 409. Another
language is opened through `/mcp-draft/translations` instead.

## Component paragraphs in the same draft

A draft save can also change the fields of paragraphs that the node references
directly. Send them in the top-level `meta`:

```json
{
  "data": {
    "type": "node--page",
    "id": "<node uuid>",
    "attributes": { "moderation_state": "draft", "title": "New title" }
  },
  "meta": {
    "mcp_components": [
      {
        "type": "paragraph--hero",
        "id": "<paragraph uuid>",
        "attributes": { "field_title": "New hero title" }
      }
    ]
  }
}
```

This follows the node edit form. Sentinel changes the paragraph objects the
draft already references, then saves the node once. Entity Reference
Revisions saves each changed paragraph as a new revision and points the draft
at it. The live revision keeps its pins, and the save rolls back if any live
pin moves. Publishing the draft makes the node and paragraph changes live
together.

Each component is checked with the same entity access, field access and
validation as the node. These are refused with 400 and nothing is written:

- a paragraph the draft does not reference directly (unrelated or nested);
- a `type` that does not match the paragraph's bundle;
- `relationships` in a component entry, or a request that also changes the
  paragraph reference field itself;
- bookkeeping fields such as `status`, `langcode` and the parent fields;
- a component listed twice;
- a paragraph held by a translatable reference field (Entity Reference
  Revisions would save that change in place, on the revision live pins);
- a translation draft (`X-MCP-Draft-Langcode` other than the default
  language).

The non-saving preflight (`X-MCP-Draft-Preflight: 1`) applies the same
checks. `GET .../mcp-translations` lists `open_draft` and `draft_components`
under `operations` on hosts that support both.

## Translations

Core JSON:API PATCH of `langcode` does not call `addTranslation()` and is not
used here. Translation writes are explicit:

- `POST .../mcp-draft/translations` creates a target-language translation as a
  new unpublished forward revision. `If-Match` is `"<live>"` when there is no
  working revision, or `"<live>:<working>"` when adding the language onto an
  existing unpublished forward revision. An existing translation on live or
  working is 409, not an overwrite.
- The same POST with `X-MCP-Draft-Mode: revise` opens that forward draft when
  the language is already published on the live default revision.
  `If-Match` is `"<live>"` when nothing is ahead of live, or
  `"<live>:<working>"` when a working copy exists (for example an English
  draft). The target translation is saved as `moderation_state: draft` and
  unpublished. The live default revision, every other language, and the
  alias stay unchanged. Over a working copy, the new revision is built on that
  working copy, so its drafts in other languages carry forward; each language's
  draft stays the latest revision that affects that language, which is where
  the core edit form and publishing look for it. An unnamed working copy is
  409 and asks for both revision IDs. A stale working id is 409. A working copy
  whose text for the target language differs from the published translation is
  409, so older copy is never carried forward (translatable stored fields are
  compared; revision metadata, timestamps, status, and moderation state are
  not). If the language is already a draft on the working copy, continue it
  instead. The default language uses the same named-working-copy revise path
  when the working copy holds only a translation draft: stale working id is
  409, and default-language text on the working copy that differs from live
  is 409. Omitting the header is still create, and create still returns the
  existing 409 when the language already exists. `GET .../mcp-translations`
  lists `revise_published_translation` in `operations` on hosts that support
  revise, and `revise_over_working_copy` on hosts that accept a named working
  copy. Preflight echoes `meta.operation: revise_published_translation`.
- `PATCH .../mcp-draft` with `X-MCP-Draft-Langcode` continues that translation
  only. Omitting the header on a multilingual working revision is 409. When
  the default language was carried onto the tip as unpublished with
  published moderation (its pending text lives on an earlier revision),
  continue restores draft moderation so that text can be corrected.
- `GET .../mcp-translations` reports live and (when the principal can view the
  unpublished revision) working languages, titles, publication, and moderation
  state, plus core `content_translation_outdated` / `content_translation_source`
  when those fields exist. Each working language includes `working_vid` (that
  language's latest translation-affected revision), `pending` (TRUE when that
  revision is an unpublished draft ahead of live), and `affected` (whether
  the tip revision marks the language translation-affected). Title, status,
  and moderation come from `working_vid`, not from the tip, so a language
  whose draft sits on an earlier revision is not reported as published.
  `meta.pending` lists those drafts; `meta.multi_pending` is TRUE when more
  than one language is pending. `GET .../mcp-draft` with the same `If-Match`
  and language header returns that working translation.
- `moderation_state` on a langcode write is allowed only when that field is
  translatable on the bundle. A shared workflow state is changed by omitting
  `X-MCP-Draft-Langcode`.

The selected translation is the entity that is validated and saved, so
content_moderation sees its unpublished draft state and does not promote the
working revision to the live default. English on the live revision — title,
summary, body, status, alias, and default revision ID — is left unchanged.
Anonymous requests do not receive working-revision languages or the draft
body. Shared aliases, file targets, and paragraph structure cannot be changed
on a translation write.

### Publishing order when more than one language is pending

Revise over a working copy (or adding a translation onto an English draft)
can leave pending drafts in more than one language, often on different
revisions. That is a valid editorial state: each language's edit form opens
its own latest translation-affected revision.

Publishing one of those languages in the Drupal UI is core behavior, not a
Sentinel save. Core builds a new default revision from the language being
published and takes every other language from the *previous* default. The
other pending drafts stop being pending. Their text remains in revision
history but disappears from the working copy and from the editor's view.
Sentinel does not hide or undo this.

When a write leaves more than one language pending, the JSON:API response
(including preflight) and `GET .../mcp-translations` include
`meta.multi_pending: true` and `meta.notices[]` with code
`multi_pending_publish`. The status report lists the same nodes as a
warning.

**Publish one language only after accepting that the others will drop.**
To recover a dropped language, open its last draft revision (`working_vid`
from the inventory taken *before* publish) and re-draft that text through
revise or continue. Prefer publishing the language whose `working_vid` is
the tip last, after the others have been published or discarded, or copy
the other drafts out first.

Paragraph *field values* use the same surface on the paragraph resource:
`POST /jsonapi/paragraph/{bundle}/{uuid}/mcp-draft/translations` with
`If-Match: "<paragraph revision ID>"` and `X-MCP-Draft-Langcode`. That
revision is the one the host already pins. The translation is unpublished.
English default-language paragraph text and live ERR UUID+vid pins stay
unchanged. Nested children are translated the same way; the parent ERR field
is not retargeted. Canonical JSON:API PATCH of a paragraph pinned by a
published host is still redirected or refused (GitHub #46).

Media items use the node contract on the media resource:
`POST /jsonapi/media/{bundle}/{uuid}/mcp-draft/translations` with the same
`If-Match` and `X-MCP-Draft-Langcode` headers creates the translation on a new
unpublished forward revision; `PATCH .../mcp-draft`, `GET .../mcp-draft`, and
`GET .../mcp-translations` work the same way. Translatable `name`, caption,
and image `alt`/`title` are copied onto the translation. The source file
target must not change: a different file UUID is refused. The live default
revision — name, alt, status, revision ID, and file reference — is left
unchanged. A bundle that is not enabled for content translation is refused
with 400 before any write.

Create the node translation first, then read its working revision and follow
that revision's paragraph references. ERR can create new child revisions when
the node creates a forward revision. Do not reuse paragraph revision IDs from
the published node inventory. For nested paragraphs, follow the working
group's child references too; UUIDs stay shared, but revision IDs can differ.

Shared-status paragraphs and saves requiring a new paragraph revision are
refused. This endpoint never repins a host revision.

Image alt is a translatable field on the host when the file target is
unchanged (`translation_sync.file: file`, alt not synced). Replacing the
file on a translation write is refused.

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
live revision would change. Create re-reads the stored working revision for
the existing-translation check so an in-memory `addTranslation()` is not
treated as a conflict. That transaction scope is required on PostgreSQL:
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

### Paragraph state and refusal contract

Paragraph draft GET, POST and PATCH responses return `meta.draft_state`. PATCH
requires that value in `X-MCP-Draft-State`, including validation-only preflights.
Re-read after a conflict; never refresh the token silently to retry old copy.
The server compares all persistent revision fields under its paragraph lock.

Paragraph status must be translatable. Shared-status bundles return 409 before
mutation, including preflight. If storage unexpectedly creates a new revision,
the transaction rolls back. Host repinning is unsupported: no historical or
current host revision is changed by this endpoint. Leave these paragraphs for
human editing until a host-aware concurrency contract is available.
