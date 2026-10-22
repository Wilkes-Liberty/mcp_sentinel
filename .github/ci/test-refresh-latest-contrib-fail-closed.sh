#!/usr/bin/env bash
# Prove each refresh-latest-contrib.sh guard is independently live.
#
# composer show --locked is checked on its own. Filtering that listing
# is a second guard. Assert the distinct stderr line for each case;
# rc != 0 alone would stay green if one guard shadowed the other.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
refresh="${here}/refresh-latest-contrib.sh"

if [ ! -f "${refresh}" ]; then
  echo "missing ${refresh}" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

show_failed_line='Failed to list locked contrib: composer show --locked failed.'
empty_list_line='Locked contrib list is empty after excluding drupal/core*. Refusing to skip latest-stable refresh.'

write_composer() {
  cat > "${tmp}/composer" <<'EOF'
#!/usr/bin/env bash
# First argument is the composer verb. Other verbs (config) are no-ops.
if [ "${1-}" = "show" ]; then
  if [ "${COMPOSER_SHOW_MODE-}" = "empty" ]; then
    printf '%s\n' 'drupal/core' 'drupal/core-recommended' 'drupal/core-dev'
    exit 0
  fi
  if [ "${COMPOSER_SHOW_MODE-}" = "partial" ]; then
    printf '%s\n' 'drupal/audit_chain'
  fi
  echo "forced composer show failure" >&2
  exit 42
fi
exit 0
EOF
  chmod +x "${tmp}/composer"
}

# Sets out, err, and rc for the caller.
run_refresh() {
  set +e
  err_file="$(mktemp)"
  out="$(PATH="${tmp}:${PATH}" bash "${refresh}" 2>"${err_file}")"
  rc=$?
  err="$(cat "${err_file}")"
  rm -f "${err_file}"
  set -e
  printf '%s\n' "${out}"
  printf '%s\n' "${err}" >&2
}

expect_fail_with_line() {
  local label="$1"
  local line="$2"
  run_refresh
  if [ "${rc}" -eq 0 ]; then
    echo "FAIL: ${label}: refresh-latest-contrib.sh exited 0" >&2
    exit 1
  fi
  if ! printf '%s\n' "${err}" | grep -Fqx "${line}"; then
    echo "FAIL: ${label}: missing stderr line: ${line}" >&2
    exit 1
  fi
  echo "OK: ${label}"
}

write_composer

echo "== composer show fails =="
export COMPOSER_SHOW_MODE=fail
expect_fail_with_line "composer show failure" "${show_failed_line}"

echo "== locked list is only drupal/core* =="
export COMPOSER_SHOW_MODE=empty
expect_fail_with_line "empty contrib list" "${empty_list_line}"

echo "== composer show fails after printing contrib =="
export COMPOSER_SHOW_MODE=partial
expect_fail_with_line "partial composer show failure" "${show_failed_line}"
