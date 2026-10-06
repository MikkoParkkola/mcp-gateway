#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The C5 / MIK-7324.COV.3 grade of one revision, in one command
# (docs/release/v4.0.0-critical-path-coverage.md, "The grade in one command").
#
#   coverage_grade.sh <rev> [tag]        probe <rev> on CI, wait, grade
#   coverage_grade.sh --run <id> <rev>   grade a finished probe run of <rev>
#   coverage_grade.sh --self-check       grade the 2026-10-06 baseline run and
#                                        require its known FAIL
#
# A probe is <rev>'s tree plus scripts/release/coverage-probe.yml as a workflow,
# committed with plumbing (no checkout is touched) and pushed to
# throwaway/coverage-grade-<tag>. Grading reads the source, inventory and grader
# of <rev> itself, so line ranges match the report. PASS needs all three: the run
# concluded success (the probe has no --ignore-run-fail, so no test failed), every
# Critical row is >=95%, and every path clears 80% and its recorded baseline.
# Needs git, gh (authenticated) and python3.
set -euo pipefail
REPO=MikkoParkkola/mcp-gateway
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$(git -C "$HERE" rev-parse --show-toplevel)"

# Baseline run at the release-line tip 409e95619 (artifacts kept 90 days, to 2027-01-04):
# one Critical row below, query_and_commit at 91.67%; every path clear.
SELF_RUN=37423361628
SELF_REV=409e95619a608d638735a3dc0ca44942e922cf08
SELF_ROW=$'BELOW\t 91.67%\t55/60\tsrc/gateway/task_service/execution/upstream.rs:query_and_commit#1'

# The probe workflow a graded run must have executed, byte for byte: this
# checkout's coverage-probe.yml, or for the self-check the definition that
# baseline run used (it predates this script).
PROBE_PATH=.github/workflows/coverage-probe.yml
PROBE_BLOB="$(git hash-object "$HERE/coverage-probe.yml")"

self_check=""
case "${1:-}" in
  --self-check)
    self_check=1; run=$SELF_RUN; rev=$SELF_REV
    PROBE_PATH=.github/workflows/coverage-cov3.yml
    PROBE_BLOB=8367614b5373f66b4f5142c15fe0afdb36c6b249
    ;;
  --run) run="${2:?--run <id> <rev>}"; rev="$(git rev-parse "${3:?--run <id> <rev>}^{commit}")" ;;
  "" | -*) echo "usage: $0 <rev> [tag] | --run <id> <rev> | --self-check" >&2; exit 2 ;;
  *)
    rev="$(git rev-parse "$1^{commit}")"
    tag="${2:-${rev:0:9}}"
    [[ "$tag" =~ ^[A-Za-z0-9-]+$ ]] || { echo "tag must match [A-Za-z0-9-]+" >&2; exit 2; }
    index="$(mktemp)"; trap 'rm -f "$index"' EXIT
    GIT_INDEX_FILE="$index" git read-tree "$rev"
    blob="$(git hash-object -w "$HERE/coverage-probe.yml")"
    GIT_INDEX_FILE="$index" git update-index --add --cacheinfo "100644,$blob,$PROBE_PATH"
    tree="$(GIT_INDEX_FILE="$index" git write-tree)"
    probe="$(git commit-tree "$tree" -p "$rev" -m "ci(throwaway): coverage grade of ${rev:0:9}")"
    branch="throwaway/coverage-grade-$tag"
    git push -q origin "$probe:refs/heads/$branch"
    echo "pushed $branch = $probe (grading $rev)"
    run=""
    for _ in $(seq 60); do
      # By file, not by name: older throwaway workflows share the name.
      run="$(gh run list -R "$REPO" --branch "$branch" --workflow "${PROBE_PATH##*/}" -L 20 \
        --json databaseId,headSha \
        -q "[.[] | select(.headSha == \"$probe\") | .databaseId][0] // empty")"
      [[ -n "$run" ]] && break
      sleep 10
    done
    [[ -n "$run" ]] || { echo "no workflow run appeared for $probe" >&2; exit 3; }
    echo "run $run"
    ;;
esac

# The run must be the pinned probe OF <rev>: it executed $PROBE_PATH, its commit's
# parent is <rev>, and that commit adds exactly $PROBE_PATH with the pinned
# content. A different workflow could check out other code; this one checks out
# its own commit, so its artifacts measure <rev>.
refuse() { echo "run $run: $*" >&2; exit 4; }
[[ "$(gh api "repos/$REPO/actions/runs/$run" -q .path)" == "$PROBE_PATH" ]] \
  || refuse "did not execute $PROBE_PATH"
head_sha="$(gh run view "$run" -R "$REPO" --json headSha -q .headSha)"
git cat-file -e "$head_sha^{commit}" 2>/dev/null || git fetch -q origin "$head_sha"
[[ "$(git rev-parse "$head_sha^")" == "$rev" ]] || refuse "probed $head_sha, whose parent is not $rev"
[[ "$(git diff --name-only "$rev" "$head_sha")" == "$PROBE_PATH" ]] \
  || refuse "probed $head_sha, which changes more than $PROBE_PATH"
[[ "$(git rev-parse "$head_sha:$PROBE_PATH")" == "$PROBE_BLOB" ]] \
  || refuse "probed $head_sha with a $PROBE_PATH that is not the pinned probe"

until [[ "$(gh run view "$run" -R "$REPO" --json status -q .status)" == completed ]]; do sleep 120; done
conclusion="$(gh run view "$run" -R "$REPO" --json conclusion -q .conclusion)"

out="$(git rev-parse --path-format=absolute --git-common-dir)/coverage-grade/$run"
rm -rf "$out"; mkdir -p "$out/src"
gh run download "$run" -R "$REPO" -D "$out/art"
git archive "$rev" src docs/release scripts/release | tar -x -C "$out/src"
paths_grader="$out/src/scripts/release/critical_path_coverage.py"
[[ -f "$paths_grader" ]] || paths_grader="$HERE/critical_path_coverage.py"

status=0
(cd "$out/src" && python3 scripts/release/critical_function_coverage.py \
  --lcov "$out/art/coverage-linux/linux.lcov" --lcov "$out/art/coverage-windows/windows.lcov") \
  > "$out/functions.txt" || status=1
python3 "$paths_grader" "$out/art/coverage-linux/cov.json" > "$out/paths.txt" || status=1
[[ "$conclusion" == success ]] || status=1

echo "== Critical rows not ok (every row: $out/functions.txt)"
grep -v '^ok' "$out/functions.txt" || true
echo "== paths"
cat "$out/paths.txt"
echo "GRADE rev=$rev run=$run conclusion=$conclusion: $([[ $status == 0 ]] && echo PASS || echo FAIL)"

if [[ -n "$self_check" ]]; then
  if [[ $status == 1 ]] && grep -qF "$SELF_ROW" "$out/functions.txt" \
    && grep -qx 'critical rows failing: 1' "$out/functions.txt" \
    && grep -qx 'paths failing: 0' "$out/paths.txt"; then
    echo "SELF-CHECK ok: the known FAIL is reproduced"
    exit 0
  fi
  echo "SELF-CHECK FAILED: the baseline grade did not reproduce" >&2
  exit 1
fi
exit "$status"
