#!/usr/bin/env bash
# Run a command as www-data with the job environment this
# layout actually needs.
#
# d.o gitlab_templates uses `sudo -u www-data -H -E`.
# GitHub's ubuntu-26.04 sudo ignores -E ("preserving the
# entire environment is not supported") and keeps going,
# so that form dropped PHP_INI_SCAN_DIR and the rest on
# the child (run 40077021782). env(1) sets the variables
# on the process regardless of sudo's preserve-env
# support. Do not add -E back; the warning is easy to
# miss and a green job with the wrong env is the failure
# this exists to stop.
set -euo pipefail

env_args=()
for var in \
  PATH \
  PHP_INI_SCAN_DIR \
  PHPRC \
  SIMPLETEST_DB \
  SIMPLETEST_BASE_URL \
  BROWSERTEST_OUTPUT_DIRECTORY \
  SYMFONY_DEPRECATIONS_HELPER \
  MCP_SENTINEL_REQUIRE_ZEND_ASSERTIONS
do
  if [ -n "${!var+x}" ]; then
    env_args+=("${var}=${!var}")
  fi
done

exec sudo -u www-data -H env "${env_args[@]}" "$@"
