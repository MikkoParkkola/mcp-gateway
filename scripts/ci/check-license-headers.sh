#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# check-license-headers.sh — enforce the affirmative per-file license boundary.
#
# Model (see LICENSES.md): the repository default is PolyForm-Noncommercial.
# Every first-party source file MUST carry an AFFIRMATIVE header — a copyright
# line plus an explicit SPDX license id — not mere absence (counsel: an extracted
# file loses its governing context, so "no header = Noncommercial" is too fragile
# to rely on in a dispute). The required header, after an optional shebang, is:
#
#     // SPDX-FileCopyrightText: <year> Mikko Parkkola
#     // SPDX-License-Identifier: <MIT | PolyForm-Noncommercial-1.0.0>
#
# MIT is allowed ONLY for files under .mit-core-allowlist; every such file MUST
# carry MIT. Everything else MUST carry the Noncommercial id. Third-party/generated
# files are out of scope and listed in .license-scope-exclude (none today).
#
# Failure modes reported:
#   - missing copyright line          (no attribution anchor)
#   - missing / unknown license id    (defaults silently — the gap counsel flagged)
#   - MIT outside the allowlist        (enterprise code leaking as free)
#   - NC inside the allowlist          (core silently became Noncommercial)
#   - MIT-core file not MIT            (allowlist promise unmet)
#
# Apply/repair with scripts/ci/apply-license-headers.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
# Comment prefix is per-file: '//' for Rust, '#' for shell. The copyright regex
# and the MIT/NC id strings accept either prefix.
COPYR_RE='^(//|#) SPDX-FileCopyrightText: [0-9]{4} Mikko Parkkola$'
MIT_ID='SPDX-License-Identifier: MIT'
NC_ID='SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0'
ALLOW=.mit-core-allowlist
EXCLUDE=.license-scope-exclude

in_list() {
  local f="$1" list="$2" p
  [ -f "$list" ] || return 1
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$p" in \#*) continue;; esac
    case "$f" in "$p"|"$p"/*) return 0;; esac
  done < "$list"
  return 1
}

no_copyright=(); bad_id=(); leaked=(); nc_in_core=(); core_not_mit=()
while IFS= read -r f; do
  in_list "$f" "$EXCLUDE" && continue
  case "$f" in *.sh) c='#' ;; *) c='//' ;; esac
  MIT="$c $MIT_ID"; NC="$c $NC_ID"

  # Header is the first two non-shebang lines.
  l1="$(head -n1 "$f")"
  case "$l1" in '#!/'*|'#! '*) hdr="$(sed -n '2,3p' "$f")";; *) hdr="$(sed -n '1,2p' "$f")";; esac
  copyr="$(printf '%s\n' "$hdr" | sed -n '1p')"
  idline="$(printf '%s\n' "$hdr" | sed -n '2p')"

  [[ "$copyr" =~ $COPYR_RE ]] || no_copyright+=("$f")

  is_mit=false; is_nc=false
  [ "$idline" = "$MIT" ] && is_mit=true
  [ "$idline" = "$NC" ]  && is_nc=true
  if ! $is_mit && ! $is_nc; then bad_id+=("$f"); fi

  if in_list "$f" "$ALLOW"; then
    $is_nc && nc_in_core+=("$f")
    $is_mit || core_not_mit+=("$f")
  else
    $is_mit && leaked+=("$f")
  fi
done < <(find src crates tests examples benches scripts deploy tools -type f \( -name '*.rs' -o -name '*.sh' \) 2>/dev/null)

rc=0
report() { local title="$1"; shift; [ "$#" -gt 0 ] || return 0; echo "error: $title" >&2; printf '  %s\n' "$@" >&2; rc=1; }
report "files missing the SPDX copyright line:"                        ${no_copyright[@]+"${no_copyright[@]}"}
report "files with a missing or unknown SPDX license id:"              ${bad_id[@]+"${bad_id[@]}"}
report "files OUTSIDE the MIT core carrying MIT (enterprise as free):"  ${leaked[@]+"${leaked[@]}"}
report "MIT-core files carrying Noncommercial (core became NC):"        ${nc_in_core[@]+"${nc_in_core[@]}"}
report "MIT-core files not carrying MIT (allowlist promise unmet):"     ${core_not_mit[@]+"${core_not_mit[@]}"}

if [ "$rc" -ne 0 ]; then
  echo "Fix with: bash scripts/ci/apply-license-headers.sh --apply   (see LICENSES.md)" >&2
else
  echo "ok: every source file carries copyright + correct SPDX id; MIT core intact, no leaks"
fi
exit $rc
