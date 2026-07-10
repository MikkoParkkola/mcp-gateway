#!/usr/bin/env bash
# apply-mit-headers.sh — add the MIT SPDX header to every .rs file under the
# MIT-core allowlist (.mit-core-allowlist). Idempotent. Everything NOT marked
# is PolyForm-Noncommercial by repository default (see LICENSES.md).
set -euo pipefail
cd "$(dirname "$0")/../.."
HDR='// SPDX-License-Identifier: MIT'
applied=0; skipped=0
while IFS= read -r p; do
  [ -z "$p" ] && continue
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    if [ "$(head -n1 "$f")" = "$HDR" ]; then skipped=$((skipped+1)); continue; fi
    # If a stale PolyForm header exists at top, replace it; else prepend.
    if head -n1 "$f" | rg -q 'SPDX-License-Identifier'; then
      # replace line 1
      tail -n +2 "$f" > "$f.tmp"; printf '%s\n' "$HDR" | cat - "$f.tmp" > "$f"; rm -f "$f.tmp"
    else
      printf '%s\n\n' "$HDR" | cat - "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    fi
    applied=$((applied+1))
  done < <(find "$p" -name '*.rs' 2>/dev/null)
done < .mit-core-allowlist
echo "MIT header: applied=$applied skipped(already)=$skipped"
