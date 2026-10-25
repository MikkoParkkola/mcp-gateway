#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The C5 / MIK-7324.COV.3 grade of one revision, in one command
# (docs/release/v4.0.0-critical-path-coverage.md, "The grade in one command").
#
#   coverage_grade.sh <rev> [tag]        probe <rev> on CI, wait, grade
#   coverage_grade.sh --run <id> <rev>   grade a finished probe run of <rev>
#   coverage_grade.sh --self-check       offline check from the vendored baseline:
#                                        its PASS reproduces and a planted FAIL is caught
#
# A probe is <rev>'s tree plus this checkout's .github/workflows/coverage-probe.yml,
# committed with plumbing (no checkout is touched) and pushed to
# throwaway/coverage-grade-<tag>. Grading reads the source, inventory and grader
# of <rev> itself, so line ranges match the report. PASS needs all three: the run
# concluded success (the probe has no --ignore-run-fail, so no test failed), every
# Critical row is >=95%, and every path clears 80% and its recorded baseline.
# A report the run should have uploaded but did not (a platform job that failed)
# is no grade at all: the last line reads NOT GRADED and the exit status is 5,
# never the 1 of a graded FAIL (MIK-8265).
# Needs git, gh (authenticated) and python3.
set -euo pipefail
REPO=MikkoParkkola/mcp-gateway
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$(git -C "$HERE" rev-parse --show-toplevel)"

# Offline self-check baseline: release-line commit 07027881e, whose grader
# inputs and outputs are vendored below (artifacts were kept 14 days then).
SELF_DIR=docs/release/baselines/coverage-39396107020
SELF_REV=07027881e

# The probe workflow a graded run must have executed, byte for byte: this
# checkout's .github/workflows/coverage-probe.yml (MIK-8217 moved it there; CI
# runs the same file).
PROBE_PATH=.github/workflows/coverage-probe.yml
PROBE_FILE="$(git rev-parse --show-toplevel)/$PROBE_PATH"
PROBE_BLOB="$(git hash-object "$PROBE_FILE")"

self_check() {
  (cd "$SELF_DIR" && shasum -a 256 -c SHA256SUMS) \
    || { echo "SELF-CHECK FAILED: baseline files do not match SHA256SUMS" >&2; exit 1; }
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/src"
  xz -dc "$SELF_DIR/linux.lcov.xz" > "$tmp/linux.lcov"
  xz -dc "$SELF_DIR/windows.lcov.xz" > "$tmp/windows.lcov"
  xz -dc "$SELF_DIR/cov.json.xz" > "$tmp/cov.json"
  rev="$(git rev-parse "$SELF_REV^{commit}")"
  git archive "$rev" src docs/release | tar -x -C "$tmp/src"
  functions=0; paths=0
  (cd "$tmp/src" && python3 "$HERE/critical_function_coverage.py" \
    --lcov "$tmp/linux.lcov" --lcov "$tmp/windows.lcov") \
    > "$tmp/functions.txt" || functions=$?
  (cd "$tmp/src" && python3 "$HERE/critical_path_coverage.py" "$tmp/cov.json") \
    > "$tmp/paths.txt" || paths=$?
  if [[ "$functions" != 0 || "$paths" != 0 ]] \
    || ! cmp -s "$tmp/functions.txt" "$SELF_DIR/functions.txt" \
    || ! cmp -s "$tmp/paths.txt" "$SELF_DIR/paths.txt"; then
    echo "SELF-CHECK FAILED: the baseline PASS did not reproduce" >&2
    exit 1
  fi
  cp "$tmp/linux.lcov" "$tmp/linux-zero.lcov"
  cp "$tmp/windows.lcov" "$tmp/windows-zero.lcov"
  python3 - "$tmp/linux-zero.lcov" "$tmp/windows-zero.lcov" <<'EOF'
import sys
target = "src/gateway/task_service/execution/upstream.rs"
for path in sys.argv[1:]:
    with open(path) as f:
        lines = f.readlines()
    in_target = False
    out = []
    for line in lines:
        if line.startswith("SF:"):
            p = line[3:].strip().replace("\\", "/")
            in_target = p.endswith(target)
            out.append(line)
        elif in_target and line.startswith("DA:"):
            num = line[3:].split(",", 1)[0]
            try:
                n = int(num)
            except ValueError:
                out.append(line)
                continue
            if 302 <= n <= 400:
                out.append("DA:%d,0\n" % n)
            else:
                out.append(line)
        else:
            if line.startswith("end_of_record"):
                in_target = False
            out.append(line)
    with open(path, "w") as f:
        f.writelines(out)
EOF
  neg=0
  (cd "$tmp/src" && python3 "$HERE/critical_function_coverage.py" \
    --lcov "$tmp/linux-zero.lcov" --lcov "$tmp/windows-zero.lcov") \
    > "$tmp/neg.txt" || neg=$?
  if [[ "$neg" == 0 ]] \
    || ! grep -E "^BELOW.*src/gateway/task_service/execution/upstream\.rs:query_and_commit#1" "$tmp/neg.txt" >/dev/null; then
    echo "SELF-CHECK FAILED: the negative control was not caught" >&2
    exit 1
  fi
  echo "SELF-CHECK ok: the baseline PASS reproduces and the planted FAIL is caught"
  exit 0
}

case "${1:-}" in
  --self-check)
    self_check
    ;;
  --run) run="${2:?--run <id> <rev>}"; rev="$(git rev-parse "${3:?--run <id> <rev>}^{commit}")" ;;
  "" | -*) echo "usage: $0 <rev> [tag] | --run <id> <rev> | --self-check" >&2; exit 2 ;;
  *)
    rev="$(git rev-parse "$1^{commit}")"
    tag="${2:-${rev:0:9}}"
    [[ "$tag" =~ ^[A-Za-z0-9-]+$ ]] || { echo "tag must match [A-Za-z0-9-]+" >&2; exit 2; }
    index="$(mktemp)"; trap 'rm -f "$index"' EXIT
    GIT_INDEX_FILE="$index" git read-tree "$rev"
    blob="$(git hash-object -w "$PROBE_FILE")"
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
# Empty when <rev> already carries the pinned workflow; the blob check below
# still pins its content.
changed="$(git diff --name-only "$rev" "$head_sha")"
[[ -z "$changed" || "$changed" == "$PROBE_PATH" ]] \
  || refuse "probed $head_sha, which changes more than $PROBE_PATH"
[[ "$(git rev-parse "$head_sha:$PROBE_PATH")" == "$PROBE_BLOB" ]] \
  || refuse "probed $head_sha with a $PROBE_PATH that is not the pinned probe"

until [[ "$(gh run view "$run" -R "$REPO" --json status -q .status)" == completed ]]; do sleep 120; done
# The two platform jobs, not the run: since MIK-8217 the run also holds CI's own
# grade job, which can fail where this script's grade differs (an older <rev>
# without critical_path_coverage.py uses the fallback below). Both jobs must
# have succeeded: no test failed and each report was produced.
conclusion="$(gh run view "$run" -R "$REPO" --json jobs -q \
  '[.jobs[] | select(.name == "llvm-cov Linux, grade" or .name == "llvm-cov Windows, grade") | .conclusion]
   | if length == 2 and all(. == "success") then "success" else "failure" end')"

grades="$(git rev-parse --path-format=absolute --git-common-dir)/coverage-grade"
out="$grades/$run"
rm -rf "$out"; mkdir -p "$out/src"
# Shared by every worktree of the clone and ~50 MB a run: keep the newest few
# plus this run (MIK-8217).
python3 "$HERE/prune_coverage_grades.py" "$grades" 3 "$run"
# A failed download is no grade either: the check below names each report it
# left absent and ends NOT GRADED (MIK-8265).
gh run download "$run" -R "$REPO" -D "$out/art" || echo "download of run $run failed or was partial"
git archive "$rev" src docs/release scripts/release | tar -x -C "$out/src"
paths_grader="$out/src/scripts/release/critical_path_coverage.py"
[[ -f "$paths_grader" ]] || paths_grader="$HERE/critical_path_coverage.py"

# A report the run should have uploaded but did not (a platform job that failed)
# is no grade at all, never a graded FAIL (MIK-8265). Checked here first, so the
# answer does not depend on <rev>'s graders, which may predate their own check;
# each grader also exits 3 on an absent, empty or unreadable report.
INPUT_MISSING=3
not_graded() {
  echo "GRADE rev=$rev run=$run conclusion=$conclusion: NOT GRADED (an input is missing; see above)"
  exit 5
}
missing=0
for input in coverage-linux/linux.lcov coverage-windows/windows.lcov coverage-linux/cov.json; do
  [[ -s "$out/art/$input" && -r "$out/art/$input" ]] || { echo "input missing: $out/art/$input"; missing=1; }
done
[[ $missing == 0 ]] || not_graded
status=0 functions=0 paths=0
(cd "$out/src" && python3 scripts/release/critical_function_coverage.py \
  --lcov "$out/art/coverage-linux/linux.lcov" --lcov "$out/art/coverage-windows/windows.lcov") \
  > "$out/functions.txt" || functions=$?
python3 "$paths_grader" "$out/art/coverage-linux/cov.json" > "$out/paths.txt" || paths=$?
if [[ $functions == "$INPUT_MISSING" || $paths == "$INPUT_MISSING" ]]; then
  grep -h '^input missing:' "$out/functions.txt" "$out/paths.txt" || true
  not_graded
fi
[[ $functions == 0 && $paths == 0 ]] || status=1
[[ "$conclusion" == success ]] || status=1

echo "== Critical rows not ok (every row: $out/functions.txt)"
grep -v '^ok' "$out/functions.txt" || true
echo "== paths"
cat "$out/paths.txt"
echo "GRADE rev=$rev run=$run conclusion=$conclusion: $([[ $status == 0 ]] && echo PASS || echo FAIL)"
exit "$status"
