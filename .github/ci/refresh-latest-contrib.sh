#!/usr/bin/env bash
# Refresh locked contrib to latest-stable matching composer.json constraints.
#
# GitHub scaffolds with drupal/recommended-project's composer.lock, then
# `composer require` of mcp_sentinel. That is a partial update: required
# contrib can stay on whatever the lock or a cached packagist snapshot
# already resolved. d.o gitlab_templates expand the module composer.json
# and `composer install` with no recommended-project lock, so they get
# today's latest-stable (DEV-1022: GitHub audit_chain 1.12.1, d.o 1.12.2).
#
# Do not update drupal/core* — matrix legs pin those. Do not add a lock
# or version pin in this repo.
set -euo pipefail

repo_cache="$(composer config --global cache-repo-dir 2>/dev/null || true)"
if [ -n "${repo_cache}" ] && [ -d "${repo_cache}" ]; then
  rm -rf "${repo_cache}"
fi

# Do not swallow a failed `composer show`. `|| true` here produced an
# empty list, skipped the refresh, and exited 0 — GitHub then tested
# pinned contrib while appearing to test latest-stable (DEV-1022).
if ! pkgs="$(composer show --locked --name-only | grep '^drupal/' | grep -vE '^drupal/core')"; then
  echo "Failed to list locked contrib for latest-stable refresh (composer show --locked failed, or no drupal/* packages remain after excluding drupal/core*)." >&2
  exit 1
fi
if [ -z "${pkgs}" ]; then
  echo "Locked contrib list is empty after excluding drupal/core*. Refusing to skip latest-stable refresh." >&2
  exit 1
fi
echo "Refreshing latest-stable contrib:"
echo "${pkgs}"
# Package names have no spaces.
# shellcheck disable=SC2086
composer update --with-dependencies --no-interaction --no-progress ${pkgs}
