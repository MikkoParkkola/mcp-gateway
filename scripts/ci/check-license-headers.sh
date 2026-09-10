#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# check-license-headers.sh — every first-party source file must carry an
# affirmative copyright line and the PolyForm-Noncommercial identifier.
#
# Model (see LICENSES.md): the repository is PolyForm-Noncommercial, whole.
# Every licensor-owned source file carries, as its first two lines (after an
# optional shebang):
#
#     // SPDX-FileCopyrightText: <year> Mikko Parkkola
#     // SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The header is affirmative on purpose: counsel flagged "absence means
# Noncommercial" as the enforceability gap, because an extracted file loses the
# context that would have said so. There is no second license and no allowlist —
# a file carrying any other identifier is an error, not a carve-out.
# Third-party/generated files are out of scope and must be listed in
# .license-scope-exclude.
set -euo pipefail
cd "$(dirname "$0")/../.."

# The copyright year is free-form (files predate and postdate any single year)
# and the NC id string accepts either comment prefix.
NC_ID='SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0'
COPYR_RE='^(//|#) SPDX-FileCopyrightText: [0-9]{4}(-[0-9]{4})? Mikko Parkkola$'
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

no_copyright=(); bad_id=()
while IFS= read -r f; do
  in_list "$f" "$EXCLUDE" && continue
  case "$f" in *.sh) c='#' ;; *) c='//' ;; esac
  NC="$c $NC_ID"

  # Header is the first two non-shebang lines.
  l1="$(head -n1 "$f")"
  case "$l1" in '#!/'*|'#! '*) hdr="$(sed -n '2,3p' "$f")";; *) hdr="$(sed -n '1,2p' "$f")";; esac
  copyr="$(printf '%s\n' "$hdr" | sed -n '1p')"
  idline="$(printf '%s\n' "$hdr" | sed -n '2p')"

  [[ "$copyr" =~ $COPYR_RE ]] || no_copyright+=("$f")
  [ "$idline" = "$NC" ] || bad_id+=("$f")
done < <(find src crates tests examples benches scripts deploy tools -type f \( -name '*.rs' -o -name '*.sh' \) 2>/dev/null)

rc=0
report() { local title="$1"; shift; [ "$#" -gt 0 ] || return 0; echo "error: $title" >&2; printf '  %s\n' "$@" >&2; rc=1; }
report "files missing the SPDX copyright line:"                       ${no_copyright[@]+"${no_copyright[@]}"}
report "files not carrying the Noncommercial SPDX identifier:"        ${bad_id[@]+"${bad_id[@]}"}

if [ "$rc" -ne 0 ]; then
  echo "Fix with: bash scripts/ci/apply-license-headers.sh --apply   (see LICENSES.md)" >&2
else
  echo "ok: every source file carries copyright + the Noncommercial SPDX id"
fi
exit $rc
