#!/usr/bin/env bash
# One-off mutant run for the Overview flow map rows (throwaway branch only, never merged).
# Baseline first: every row named in the manifest must pass on the clean tree, else
# every mutant is VOID. Then, per manifest row: apply the patch to the clean tree,
# run only its rows in chromium with no retries, judge from Playwright's own summary
# line, and revert. One verdict line per mutant in mutant-out/verdicts.tsv:
#   KILLED    the run exited non-zero, Playwright reported a failed row, and an expect() failed
#   SURVIVED  the run exited 0 and at least one row passed
#   VOID      the grep selected no row, the patch did not apply, no row ran, the failure was not an
#             assertion (browser or fixture setup), or the tree could not be restored (the loop stops)
# Run from ui-tests/: bash mutants-9593/run.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# Not under test-results/: Playwright empties that folder at the start of every run.
out=mutant-out
mkdir -p "$out"
verdicts="$out/verdicts.tsv"
printf 'id\tverdict\trc\tfailed\tpassed\tselected\tfirst failing row\n' > "$verdicts"
aborted=0

# Runs the rows matching $3 in spec $2, logs to $out/$1.log; prints "rc failed passed".
rows() {
  local log="$out/$1.log"
  npx playwright test --project=chromium --reporter=line --retries=0 "$2" -g "$3" > "$log" 2>&1
  local rc=$?
  local failed passed
  failed=$(grep -oE '^ *[0-9]+ failed' "$log" | tail -1 | grep -oE '[0-9]+')
  passed=$(grep -oE '^ *[0-9]+ passed' "$log" | tail -1 | grep -oE '[0-9]+')
  echo "$rc ${failed:-0} ${passed:-0}"
}

clean() { git -C "$root" diff --quiet -- src; }

clean || { echo "run.sh: src/ is not clean at the start" >&2; exit 2; }

# Baseline: the flow map's spec whole (every row the manifest names) and the panel order rows, on the clean tree.
npx playwright test --project=chromium --reporter=line --retries=0 tests/overview-flowmap.spec.mjs tests/overview-panels.spec.mjs > "$out/baseline.log" 2>&1
base_rc=$?
base_ok=0
[ "$base_rc" = 0 ] && grep -qE '^ *[0-9]+ passed' "$out/baseline.log" && base_ok=1
echo "baseline rc=$base_rc ok=$base_ok $(grep -oE '^ *[0-9]+ (passed|failed)' "$out/baseline.log" | tr -s ' ' | tr '\n' ' ')" | tee "$out/baseline.txt"
[ "$base_ok" = 1 ] || { echo "--- baseline failures"; grep -m3 -A30 -E '^ +Error: ' "$out/baseline.log"; }

while IFS=$'\t' read -r id patch spec grep; do
  case "$id" in '#'*|'') continue ;; esac
  if [ "$base_ok" != 1 ]; then
    printf '%s\tVOID\t-\t-\t-\tbaseline red\n' "$id" >> "$verdicts"
    continue
  fi
  if [ "$aborted" = 1 ]; then
    printf '%s\tVOID\t-\t-\t-\t-\ttree not restored after an earlier mutant\n' "$id" >> "$verdicts"
    continue
  fi
  # The rows this entry selects, listed before any patch (no browser): none selected is VOID.
  npx playwright test --project=chromium --list "$spec" -g "$grep" > "$out/$id.selected.txt" 2>&1
  selected=$(grep -c '›' "$out/$id.selected.txt")
  if [ "$selected" = 0 ]; then
    printf '%s\tVOID\t-\t-\t-\t0\tthe grep selects no row\n' "$id" >> "$verdicts"
    continue
  fi
  if ! git -C "$root" apply "$here/$patch"; then
    printf '%s\tVOID\t-\t-\t-\t%s\tpatch did not apply\n' "$id" "$selected" >> "$verdicts"
    continue
  fi
  read -r rc failed passed < <(rows "$id" "$spec" "$grep")
  # Playwright's numbered failure list: "  1) [chromium] › <file> › <title>".
  first=$(grep -m1 -oE '^ +1\) \[chromium\] › .*' "$out/$id.log" | sed -E 's/^ +1\) //' | cut -c1-160)
  # A kill needs a failed assertion, not a browser or fixture setup error.
  # Both forms: "Error: expect(...) failed" and "Error: Timed out ... waiting for expect(...)".
  asserted=$(grep -cE 'Error: .*expect\(|^ +expect\((locator|received|page)\)\.' "$out/$id.log")
  # A labelled expect prints "Error: <label>" and the expect( line under it (round 1 F2 and F12).
  if [ "$rc" != 0 ] && [ "$failed" -gt 0 ] && [ "$asserted" -gt 0 ]; then verdict=KILLED
  elif [ "$rc" = 0 ] && [ "$passed" -gt 0 ]; then verdict=SURVIVED
  elif [ "$rc" != 0 ] && [ "$failed" -gt 0 ]; then verdict="VOID(no assertion failed)"
  else verdict=VOID
  fi
  git -C "$root" apply -R "$here/$patch" || { git -C "$root" checkout -- src && verdict="$verdict(revert-checkout)"; }
  if ! clean; then
    git -C "$root" checkout -- src
    if ! clean; then
      aborted=1
      verdict="VOID(was $verdict; tree not restored; loop aborted)"
    fi
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$verdict" "$rc" "$failed" "$passed" "$selected" "${first:--}" | tee -a "$verdicts"
  # Artifacts are not downloaded: any verdict but KILLED prints its first error block into the job log.
  [ "$verdict" = KILLED ] || { echo "--- $id first error block"; grep -m1 -A30 -E '^ +Error: ' "$out/$id.log"; }
done < "$here/manifest.tsv"

grep '^# K33' "$here/manifest.tsv" | sed 's/^# //' >> "$verdicts"
echo "done: $(grep -c $'\tKILLED' "$verdicts") killed, $(grep -c $'\tSURVIVED' "$verdicts") survived, $(grep -c $'\tVOID' "$verdicts") void"
