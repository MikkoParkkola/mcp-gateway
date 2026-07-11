#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# apply-mit-headers.sh — reconcile MIT SPDX headers to match .mit-core-allowlist.
# Files under an allowlist path get `// SPDX-License-Identifier: MIT` as line 1;
# every other .rs file must NOT have it (stripped if present). Everything
# unmarked is PolyForm-Noncommercial by repository default (see LICENSES.md).
# Idempotent. Scans src/ AND crates/ (repo-wide per-file rule).
set -euo pipefail
cd "$(dirname "$0")/../.."
HDR='// SPDX-License-Identifier: MIT'
ALLOW=.mit-core-allowlist

in_allow() {
  local f="$1" p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$f" in "$p"|"$p"/*) return 0;; esac
  done < "$ALLOW"
  return 1
}

added=0; stripped=0; kept=0
while IFS= read -r f; do
  has=false; [ "$(head -n1 "$f")" = "$HDR" ] && has=true
  if in_allow "$f"; then
    if $has; then kept=$((kept+1)); else
      printf '%s\n\n' "$HDR" | cat - "$f" > "$f.tmp" && mv "$f.tmp" "$f"; added=$((added+1))
    fi
  else
    if $has; then
      # strip line 1 (the MIT header) and a following blank line if present
      tail -n +2 "$f" > "$f.tmp"; [ -z "$(head -n1 "$f.tmp")" ] && tail -n +2 "$f.tmp" > "$f.tmp2" && mv "$f.tmp2" "$f.tmp"
      mv "$f.tmp" "$f"; stripped=$((stripped+1))
    fi
  fi
done < <(find src crates -name '*.rs' 2>/dev/null)
echo "MIT headers reconciled: added=$added stripped=$stripped kept=$kept"
