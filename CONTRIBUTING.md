# Contributing — mcp_sentinel

See `internal/CONTRIBUTING.md` for the full Wilkes Liberty branching/commit policy.

---

## Jira Issue Keys in Branches & Commits — REQUIRED (2026-06)

> This policy is authoritative and supersedes any generic `feature/descriptive-name` examples elsewhere in this file. Canonical copy: `internal/CONTRIBUTING.md`.

We run **GitHub for Atlassian** (Wilkes-Liberty org, all repos). It links GitHub activity to Jira **by issue key**, populating each issue's Development panel. **No key ⇒ no link, no traceability.**

**Branch name (required):** `type/ISSUE-KEY-short-slug`
- `type` ∈ {feature, fix, chore, hotfix, spike}; **KEY uppercase**; slug lowercase-hyphenated.
- Use the key of the **Jira issue** (not the repo): code → `DEV-`, content → `CON-`, infra/ops → `IT-`, gov → `GOV-`.
- ✅ `feature/DEV-4-graphql-upgrade`, `fix/IT-1-wan-flapping`, `chore/CON-13-homepage`
- ❌ colons/brackets/spaces (invalid git refs) — not `feature/DEV-4:[Title]`; ❌ no-key names like `my-fix`.

**Commit subject:** start with the key — `DEV-4 Bump drupal/graphql 4→5`.

**Smart Commits** (key first, then commands): `#comment <text>`, `#time 2h 30m`, `#<transition>` (status/column name, hyphenated). Example: `DEV-11 Wire revalidate #time 45m #comment busts on save #review`.

**PR title:** include the key — `DEV-4: Upgrade drupal/graphql 4→5`.

**Migration note:** old `WEBCMS-*` / old infra `WL-*` keys are retired (issues moved to `DEV-*`/`CON-*`/`IT-*`); use current keys only.
