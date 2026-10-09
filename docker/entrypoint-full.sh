#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -eu

DROPIN_DIR=/docker-entrypoint.d
INSTALL_TIMEOUT=300

# The child a stop would interrupt: the install, or one startup step. PID 1
# with no handler installed ignores SIGTERM, and a trap is deferred until a
# foreground child exits, so every child is started in the background and
# waited on, which a trap can interrupt.
current_child=
on_term() {
  if [ -n "$current_child" ]; then
    kill -TERM "$current_child" 2>/dev/null || true
    wait "$current_child" 2>/dev/null || true
  fi
  exit 143
}
trap on_term TERM INT

run_child() {
  "$@" &
  current_child=$!
  rc=0
  wait "$current_child" || rc=$?
  current_child=
  return "$rc"
}

run_dropins() {
  for f in "$DROPIN_DIR"/*; do
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
    rc=0
    if [ "${f##*.}" = envsh ]; then
      # Sourced, not run: this is the shell whose environment the gateway execs
      # with, and a sourced file cannot be backgrounded.
      # shellcheck disable=SC1090
      . "$f" || rc=$?
    else
      run_child "$f" || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
      echo "entrypoint: $f failed (exit $rc)" >&2
      exit 1
    fi
  done
}

install_declared_packages() {
  # Globbing off while the list is split into words, so a name carrying a glob
  # character reaches apt as written.
  set -f
  # shellcheck disable=SC2086
  set -- ${EXTRA_APT_PACKAGES}
  set +f
  # Only blanks: nothing to install, so no update either.
  [ "$#" -gt 0 ] || return 0
  # A word starting with `-` is an apt option, not a package: `--simulate x`
  # makes apt exit 0 having installed nothing, and the container would start
  # without what it declared. A word ending in `-` asks apt-get install to
  # remove that package. Both are refused before apt runs.
  for word in "$@"; do
    case "$word" in
      -*|*-)
        echo "entrypoint: EXTRA_APT_PACKAGES holds an apt option or removal ($word); list package names only" >&2
        exit 1
        ;;
    esac
  done
  export DEBIAN_FRONTEND=noninteractive
  # Bounded because apt is the one startup step that waits on something outside
  # the deployment.
  rc=0
  run_child timeout -k 15 "$INSTALL_TIMEOUT" sh -c \
    'apt-get update -qq && apt-get install -y --no-install-recommends "$@"' \
    entrypoint-apt "$@" || rc=$?
  # A failing link in an `&&` list does not end a `set -e` script, so the chain
  # above reports through its status and the failure is carried here instead.
  if [ "$rc" -ne 0 ]; then
    echo "entrypoint: EXTRA_APT_PACKAGES install failed (exit $rc)" >&2
    exit 1
  fi
  # The indexes were only needed by the chain that just ran. The directory is
  # removed whole, so no glob is involved.
  rm -rf /var/lib/apt/lists
}

if [ "$(id -u)" = 0 ]; then
  if [ -n "${EXTRA_APT_PACKAGES:-}" ]; then
    install_declared_packages
  fi
  run_dropins
  # `--init-groups` resolves the groups from the image's own database, where a
  # numeric id is whatever this distribution happened to put in it.
  exec env HOME=/home/gateway \
    setpriv --reuid=gateway --regid=gateway --init-groups mcp-gateway "$@"
fi

run_dropins
exec mcp-gateway "$@"
