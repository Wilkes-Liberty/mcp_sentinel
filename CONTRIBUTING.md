# Contributing to MCP Sentinel

Thanks for helping improve MCP Sentinel. Contributions of all kinds are welcome —
bug reports, patches, docs, and test coverage.

## Where development happens

- **Primary repository (issues + pull requests):**
  [github.com/Wilkes-Liberty/mcp_sentinel](https://github.com/Wilkes-Liberty/mcp_sentinel)
- **Mirror:** [git.drupalcode.org/project/mcp_sentinel](https://git.drupalcode.org/project/mcp_sentinel)
- **Releases:** [drupal.org/project/mcp_sentinel](https://www.drupal.org/project/mcp_sentinel)
  (installable with Composer)

Open issues and pull requests on GitHub. The drupalcode.org repository is a mirror
that carries release branches and tags so `packages.drupal.org` can build the
Composer package; you do not need to interact with it to contribute.

## Where to file things

- **Bugs and feature requests:** GitHub issues on the primary repository (preferred)
  or the [drupal.org issue queue](https://www.drupal.org/project/issues/mcp_sentinel).
- **Security vulnerabilities:** see [SECURITY.md](SECURITY.md) — never in a
  public issue.

## Branches

- `1.x` is the active development and release branch.
- Branch your work off `1.x` with a short, descriptive name:
  `feature/<slug>`, `fix/<slug>`, or `chore/<slug>` (lowercase, hyphenated).
- Open your pull request against `1.x`.

## Making a change

1. Fork and branch off `1.x`.
2. Make your change, following Drupal coding standards (see below).
3. Add or update tests for any behavior change.
4. Add an entry under `## [Unreleased]` in `CHANGELOG.md` (a CI check enforces
   this; trivial PRs may use the `no-changelog` label).
5. Open a pull request with a clear description of the problem and the fix.

## Coding standards & checks

This module targets Drupal 10.6+/11.3+ and PHP 8.3+. Please run the same checks
CI runs:

```bash
# Drupal coding standards (use the committed ruleset)
phpcs --standard=phpcs.xml.dist .

# Static analysis
phpstan analyse -c phpstan.neon.dist

# Tests (from a Drupal codebase that contains the module)
phpunit -c web/core web/modules/contrib/mcp_sentinel
```

Security-relevant changes (policy resolution, role assertions, audit logging,
break-glass, raw SQL, OAuth channel detection) should include a test that fails
without the fix.

## Documentation

Update `README.md`, `CHANGELOG.md` (under `[Unreleased]`), and the docs in
`docs/` for any user-facing change. Keep operator-facing copy plain and
specific — lead with the concrete behavior, not with how impressive the
mechanism is.

## License

By contributing, you agree that your contributions are licensed under the
[GPL-2.0-or-later](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
license that covers the project.
