#!/bin/bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The add-server mutant legs, one after another, from ui-tests/ (the workflow's
# working directory). legs.tsv lists each leg: id, hunk count, killing line, and
# the row's title text (passed to -g, so it must not hold regex characters).
# Per leg: check the patch's hunk count, apply it, rehash so the served file is
# the mutant, run only that row with no retries, judge it at its killing line,
# then put src/gateway/ui back exactly as committed. A CONTROL leg applies
# nothing. The verdicts are summed up at the end; the job itself always passes,
# since the verdicts, not the exit status, are the result.
set -u
mkdir -p mutant-out
restore() {
  git -C .. checkout -q -- src/gateway/ui
  git -C .. clean -q -f -d -- src/gateway/ui
}
while IFS=$'\t' read -r id hunks line row; do
  case "$id" in ''|'#'*) continue ;; esac
  echo "== $id"
  if [ "$hunks" != 0 ]; then
    got=$(grep -c '^@@' "mutants-9566/$id.patch")
    if [ "$got" != "$hunks" ]; then echo "VERDICT INVALID ($id: $got hunks, the list says $hunks)" | tee "mutant-out/$id.verdict"; continue; fi
    if ! git -C .. apply "ui-tests/mutants-9566/$id.patch"; then echo "VERDICT INVALID ($id: the patch does not apply)" | tee "mutant-out/$id.verdict"; continue; fi
    python3 -I ../scripts/dev/rehash_ui_assets.py > "mutant-out/$id.rehash.txt" 2>&1
  fi
  PLAYWRIGHT_JSON_OUTPUT_NAME="mutant-out/$id.json" npx playwright test --project=chromium --retries=0 --reporter=json \
    tests/server-add.spec.mjs -g "$row" > "mutant-out/$id.log" 2>&1
  node mutants-9566/judge.mjs "mutant-out/$id.json" server-add.spec.mjs "$line" | tee "mutant-out/$id.verdict"
  restore
done < mutants-9566/legs.tsv
echo "== summary"
for f in mutant-out/*.verdict; do printf '%s: ' "$(basename "$f" .verdict)"; head -n 1 "$f"; done
