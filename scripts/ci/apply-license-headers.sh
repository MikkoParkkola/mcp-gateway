#!/usr/bin/env bash
# apply-license-headers.sh — stamp affirmative SPDX headers on every source file.
#
# Counsel (grok-4.5 + gpt-5.6-sol, both FIX FIRST) flagged "absence = Noncommercial"
# as the biggest enforceability gap: an extracted file loses its governing context.
# The fix is an AFFIRMATIVE per-file header — copyright + explicit SPDX license id —
# on every licensor-owned source file, not mere absence.
#
# Model (see LICENSES.md):
#   - Files under .mit-core-allowlist  -> MIT.
#   - Every other first-party source   -> PolyForm-Noncommercial-1.0.0.
# Both get the copyright line. Third-party/generated files are out of scope and
# must be listed in .license-scope-exclude (none today; the repo has no vendored
# or generated .rs — verified: no @generated markers, no build.rs).
#
# Idempotent: re-running is a no-op. Shebang lines are preserved (header inserted
# after them). DRY-RUN by default; pass --apply to write.
set -euo pipefail
cd "$(dirname "$0")/../.."

APPLY=false; [ "${1:-}" = "--apply" ] && APPLY=true
COPYR='// SPDX-FileCopyrightText: 2026 Mikko Parkkola'
MIT='// SPDX-License-Identifier: MIT'
NC='// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0'
ALLOW=.mit-core-allowlist
EXCLUDE=.license-scope-exclude   # third-party/generated paths, one per line (optional)

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

changed=0; skipped=0
while IFS= read -r f; do
  if in_list "$f" "$EXCLUDE"; then skipped=$((skipped+1)); continue; fi
  if in_list "$f" "$ALLOW"; then id="$MIT"; else id="$NC"; fi

  # Split optional shebang from the body. A shebang is '#!/...' or '#! ...';
  # Rust inner attributes ('#![...]') are NOT shebangs and must stay in the body.
  first="$(head -n1 "$f")"
  case "$first" in
    '#!/'*|'#! '*) shebang="$first"; body_start=2 ;;
    *)             shebang="";       body_start=1 ;;
  esac

  # Rebuild: shebang (if any) -> canonical 2-line header -> body with any existing
  # leading SPDX copyright/identifier lines stripped (NR<=4 = still in header run),
  # so re-runs and pre-existing MIT-line-1 files converge idempotently.
  tmp="$(mktemp)"
  {
    [ -n "$shebang" ] && printf '%s\n' "$shebang"
    printf '%s\n' "$COPYR"
    printf '%s\n' "$id"
    tail -n +"$body_start" "$f" \
      | awk 'NR<=4 && /^\/\/ SPDX-(FileCopyrightText|License-Identifier)/ {next} {print}'
  } > "$tmp"

  if cmp -s "$tmp" "$f"; then
    rm -f "$tmp"; skipped=$((skipped+1))
  else
    changed=$((changed+1))
    if $APPLY; then mv "$tmp" "$f"; else echo "would stamp [$id]: $f"; rm -f "$tmp"; fi
  fi
done < <(find src crates tests examples benches -name '*.rs' 2>/dev/null | sort)

echo "headers: $changed to stamp, $skipped already-correct/excluded"
$APPLY || echo "(dry-run — re-run with --apply to write)"
