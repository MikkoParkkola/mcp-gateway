#!/usr/bin/env bash
# check-license-headers.sh — enforce the per-file license boundary.
#
# Model (see LICENSES.md): the repository default is PolyForm-Noncommercial.
# Only files under the paths in .mit-core-allowlist may carry the MIT SPDX
# header, and every such file MUST carry it. Any MIT header OUTSIDE the
# allowlist is a leak (enterprise code marked free) and fails CI. Any allowlist
# file MISSING the header is also a failure (core silently became NC).
#
# This replaces the earlier EE-allowlist checker: with NC-as-default we police
# the small, auditable MIT surface instead of trying to enumerate all EE files.
set -euo pipefail
cd "$(dirname "$0")/../.."
MIT='// SPDX-License-Identifier: MIT'
ALLOW=.mit-core-allowlist

# Build a predicate: is path $1 inside an allowlist entry?
in_allow() {
  local f="$1" p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$f" in "$p"|"$p"/*) return 0;; esac
  done < "$ALLOW"
  return 1
}

missing=(); leaked=()
while IFS= read -r f; do
  has_mit=false
  [ "$(head -n1 "$f")" = "$MIT" ] && has_mit=true
  if in_allow "$f"; then
    $has_mit || missing+=("$f")
  else
    $has_mit && leaked+=("$f")
  fi
done < <(find src -name '*.rs')

rc=0
if [ "${#missing[@]}" -gt 0 ]; then
  echo "error: MIT-core files missing the '$MIT' header (they would default to Noncommercial):" >&2
  printf '  %s\n' "${missing[@]}" >&2; rc=1
fi
if [ "${#leaked[@]}" -gt 0 ]; then
  echo "error: files OUTSIDE the MIT core carry an MIT header (enterprise code leaking as free):" >&2
  printf '  %s\n' "${leaked[@]}" >&2
  echo "Remove the MIT header, or add the path to .mit-core-allowlist if it is genuinely core. See LICENSES.md." >&2
  rc=1
fi
[ "$rc" -eq 0 ] && echo "ok: license boundary intact — MIT core all headered, no MIT leaks outside it"
exit $rc
