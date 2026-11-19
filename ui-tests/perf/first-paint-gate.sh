#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The first-paint gate with its retries, run from inside the worktree to judge:
#   ui-tests/perf/first-paint-gate.sh <nightly|ready|proof|verdicts|calibrate> <sha> <owner>
# <owner> is the spark-slot owner: the lane's own name (its two-job cap applies), or first-paint for the nightly.
# Each attempt takes one full Spark slot (spark-slot run), so no slot is held while waiting. A busy host
# (exit 3) is retried every 15 minutes for up to 6 hours, then reported as "no quiet window found", never
# a pass. A Mac-side network drop (exit 75) is retried once. Drift (exit 4), faults and failures are final.
set -uo pipefail
mode=${1:?mode} sha=${2:?sha} owner=${3:?owner}
# From the repo root with a relative path, so the job runs the launcher from spark-slot's snapshot.
cd "$(git rev-parse --show-toplevel)" || exit 2
case "$mode" in
	verdicts) export SPARK_SLOT_MAX_MINUTES=120 ;; # ~500 runs, about 85 minutes
	calibrate) export SPARK_SLOT_MAX_MINUTES=100 ;; # 370 runs, about 65 minutes
esac
deadline=$(($(date +%s) + 6 * 3600))
dropped=0
while :; do
	spark-slot run full "$owner" "first-paint-$mode" -- ui-tests/perf/first-paint-launch.sh "$mode" "$sha"
	rc=$?
	if [ "$rc" -eq 75 ] && [ "$dropped" -eq 0 ]; then dropped=1; echo "Spark unreachable once (75); retrying"; continue; fi
	[ "$rc" -eq 3 ] || exit "$rc"
	if [ $(($(date +%s) + 900)) -gt "$deadline" ]; then echo "no quiet window found in 6 hours (exit 3)"; exit 3; fi
	echo "busy host (exit 3) at $(date -u +%H:%MZ); retrying in 15 minutes"
	sleep 900
done
