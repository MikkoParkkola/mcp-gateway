#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Which commits cited as release evidence are not on the release line?
#
# Ancestry alone over-reports: the release line squash-merges, and a squash
# lands its branch under a new identity, so every pre-squash commit is absent
# by ancestry forever. This checks ancestry first, then asks whether the
# subject of each absent commit appears in a commit body on the line -- which
# is how a squash records what it carried.
#
# `git cherry` is the wrong tool here and is deliberately not used: it compares
# per-commit patch ids, and a squash produces one patch matching none of them.
set -uo pipefail

LINE="${1:-origin/main}"
LEDGER="${2:-docs/requirements/RELEASE-4.0.0-criteria-status.md}"

cited=$(rg -o '`[0-9a-f]{8,40}`' "$LEDGER" | tr -d '`' | sort -u)
printf 'line=%s  ledger=%s  cited=%s\n\n' \
  "$LINE" "$LEDGER" "$(printf '%s\n' "$cited" | grep -c .)"

not_a_commit=0 carried=0 unaccounted=0

for sha in $cited; do
  if ! git rev-parse --verify --quiet "$sha" >/dev/null 2>&1; then
    printf 'NOT-A-COMMIT %s (correct the ledger: a run id or a typo)\n' "$sha"
    not_a_commit=$((not_a_commit + 1))
    continue
  fi
  git merge-base --is-ancestor "$sha" "$LINE" 2>/dev/null && continue

  subject=$(git log -1 --format='%s' "$sha")
  bearer=$(git log "$LINE" --format='%h' --fixed-strings --grep="$subject" | head -1)
  if [ -n "$bearer" ]; then
    printf 'CARRIED      %s -> %s  %s\n' "$sha" "$bearer" "${subject:0:60}"
    carried=$((carried + 1))
  else
    printf 'UNACCOUNTED  %s              %s\n' "$sha" "${subject:0:60}"
    unaccounted=$((unaccounted + 1))
  fi
done

printf '\ncarried-by-squash=%s  unaccounted=%s  not-a-commit=%s\n' \
  "$carried" "$unaccounted" "$not_a_commit"

# A CARRIED verdict says the squash body names the commit, not that every line
# it wrote survived: the reconcile merge b3f05fd4 dropped production code that
# 0f04a179 had carried. Confirm a row by locating its cited files and test
# names at the line's tip, the way MIK-7332.DISCOVERY.1 was graded.
[ "$unaccounted" -eq 0 ]
