# Changelog authoring and release preparation

For a release-worthy change, add one uniquely named
`changelog.d/<issue>-<slug>.md`. Keep ordinary pull requests out of
`CHANGELOG.md`; independent filenames avoid adjacent-line conflicts.

```markdown
---
section: Fixed
---
Describe the observable correction and why it matters.
```

Use Added, Changed, Deprecated, Removed, Fixed or Security. The `changelog`
label remains opt-in: unlabelled pull requests do not require a note, and
Dependabot retains its exemption. A note that is present must be well formed.
Module behavior issues retain their Drupal.org issue identifiers. Concurrent
PRs on the same issue need different slugs.

The reusable checker is published in shared-ci and called at `@v1`. It verifies
fragment syntax, conflict markers, pending section structure and unchanged
release history. Existing status names remain available to branch protection.
A caller does not automatically make new checks required in repository settings.

For release preparation, obtain `.github/scripts/changelog-fragments.py` from
the same verified shared-ci revision as the workflow. Set
`SHARED_CHANGELOG_TOOL` to that local file, then use an isolated preparation branch:

```sh
python3 -I "$SHARED_CHANGELOG_TOOL" check --preserve-history --extra-sections Docs,Documentation,Dependencies,Tests
python3 -I "$SHARED_CHANGELOG_TOOL" render --preserve-history --extra-sections Docs,Documentation,Dependencies,Tests --version X.Y.Z --date YYYY-MM-DD
python3 -I "$SHARED_CHANGELOG_TOOL" compile --preserve-history --extra-sections Docs,Documentation,Dependencies,Tests --version X.Y.Z --date YYYY-MM-DD
```

Replace the version and date explicitly. Preview is read-only. Compile carries
inherited pending notes forward, archives all fragments exactly once and removes
the consumed files. Earlier archives stay unchanged. Review and commit the
archive plus deletions together, then verify the committed diff:

```sh
python3 -I "$SHARED_CHANGELOG_TOOL" check --preserve-history --extra-sections Docs,Documentation,Dependencies,Tests --enforce-fragments --base origin/1.x
```

Use the repository's GitHub remote name if it is not `origin`. Complete existing
release tests and metadata checks before publication. A compile is preparation,
not a release. Do not consume candidate notes before the project's release
procedure calls for finalization.
