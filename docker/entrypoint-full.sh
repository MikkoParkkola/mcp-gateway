#!/bin/sh
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -eu

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
    set -f
    # shellcheck disable=SC2086
    apt-get update -qq \
      && apt-get install -y --no-install-recommends ${EXTRA_APT_PACKAGES} \
      && rm -rf /var/lib/apt/lists/*
    set +f
  fi
  run_dropins
  exec env HOME=/home/gateway setpriv --reuid=1001 --regid=1001 --groups=100 mcp-gateway "$@"
fi

run_dropins
exec mcp-gateway "$@"
