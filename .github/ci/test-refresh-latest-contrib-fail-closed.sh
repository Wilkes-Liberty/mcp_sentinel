#!/usr/bin/env bash
# Prove refresh-latest-contrib.sh fails closed.
#
# A PATH `composer` whose `show` exits non-zero, or one that lists only
# drupal/core*, must fail this script. With `|| true` on the composer-show
# pipeline (and exit 0 on an empty list) both cases exit 0 and this check
# fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
refresh="${here}/refresh-latest-contrib.sh"

if [ ! -f "${refresh}" ]; then
  echo "missing ${refresh}" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

write_composer() {
  cat > "${tmp}/composer" <<'EOF'
#!/usr/bin/env bash
# First argument is the composer verb. Other verbs (config) are no-ops.
if [ "${1-}" = "show" ]; then
  if [ "${COMPOSER_SHOW_MODE-}" = "empty" ]; then
    printf '%s\n' 'drupal/core' 'drupal/core-recommended' 'drupal/core-dev'
    exit 0
  fi
  echo "forced composer show failure" >&2
  exit 42
fi
exit 0
EOF
  chmod +x "${tmp}/composer"
}

run_refresh() {
  set +e
  out="$(PATH="${tmp}:${PATH}" bash "${refresh}" 2>&1)"
  rc=$?
  set -e
  printf '%s\n' "${out}"
  return "${rc}"
}

write_composer

echo "== composer show fails =="
export COMPOSER_SHOW_MODE=fail
if run_refresh; then
  echo "FAIL: refresh-latest-contrib.sh exited 0 after composer show failed" >&2
  exit 1
fi
echo "OK: composer show failure exited non-zero"

echo "== locked list is only drupal/core* =="
export COMPOSER_SHOW_MODE=empty
if run_refresh; then
  echo "FAIL: refresh-latest-contrib.sh exited 0 with no contrib to refresh" >&2
  exit 1
fi
echo "OK: empty contrib list exited non-zero"
