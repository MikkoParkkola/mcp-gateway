#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Entrypoint of the `-full` variant.
#
# Started as root (`--user root`, a deployment's choice), it installs the apt
# packages EXTRA_APT_PACKAGES names, runs /docker-entrypoint.d, and drops to
# the gateway user before exec'ing the gateway. Started as the image's own
# user, it only runs the drop-ins. A failed or timed-out install, and a failing
# drop-in, stop the container rather than start it without what it declared.
set -eu

APT_TIMEOUT="${EXTRA_APT_TIMEOUT:-300}"

refuse() {
  echo "entrypoint: $*; not starting" >&2
  exit 1
}

# Both values reach a command line. A timeout of 0 means "no limit" to
# `timeout`, and a token starting with `-` is an apt option (`--simulate`
# installs nothing and succeeds), so either would defeat the fail-closed
# install. Checked before anything runs.
check_install_inputs() {
  case "${APT_TIMEOUT}" in
    '' | *[!0-9]* | 0*) refuse "EXTRA_APT_TIMEOUT must be a positive whole number of seconds, not '${APT_TIMEOUT}'" ;;
  esac
  set -f
  # shellcheck disable=SC2086
  for package in ${EXTRA_APT_PACKAGES}; do
    case "${package}" in
      -*) refuse "EXTRA_APT_PACKAGES names packages only, not the apt option '${package}'" ;;
    esac
  done
  set +f
}

# Run one install step in the background and wait on it, so PID 1 can answer
# `docker stop` mid-install: a shell does not run a trap while a foreground
# child runs. `timeout` bounds a mirror that stops answering.
bounded() {
  timeout -k 10 "${APT_TIMEOUT}" env DEBIAN_FRONTEND=noninteractive "$@" &
  pid=$!
  trap 'kill -TERM "${pid}" 2>/dev/null; exit 143' TERM INT
  status=0
  wait "${pid}" || status=$?
  trap - TERM INT
  return "${status}"
}

install_packages() {
  check_install_inputs
  if ! bounded apt-get update -qq; then
    refuse "apt-get update failed or exceeded ${APT_TIMEOUT}s"
  fi
  # The value must word-split into several names; it must not glob.
  set -f
  # shellcheck disable=SC2086
  if ! bounded apt-get install -y --no-install-recommends ${EXTRA_APT_PACKAGES}; then
    refuse "installing '${EXTRA_APT_PACKAGES}' failed or exceeded ${APT_TIMEOUT}s"
  fi
  set +f
  rm -rf /var/lib/apt/lists/*
}

run_dropins() {
  for f in /docker-entrypoint.d/*; do
    [ -f "$f" ] || continue
    case "$f" in
      *.sh|*.envsh) ;;
      *) continue ;;
    esac
    if [ ! -x "$f" ]; then
      echo "entrypoint: ignoring $f, not executable" >&2
      continue
    fi
    echo "entrypoint: running $f" >&2
    if [ "${f##*.}" = envsh ]; then
      # shellcheck disable=SC1090
      . "$f"
    else
      "$f"
    fi
  done
}

if [ "$(id -u)" = 0 ]; then
  if [ -n "${EXTRA_APT_PACKAGES:-}" ]; then
    install_packages
  fi
  run_dropins
  exec env HOME=/home/gateway setpriv --reuid=gateway --regid=gateway --init-groups mcp-gateway "$@"
fi

run_dropins
exec mcp-gateway "$@"
