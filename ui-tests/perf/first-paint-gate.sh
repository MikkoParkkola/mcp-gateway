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
# READY modes read the nightly record first (written on this Mac by first-paint-nightly.sh). A missing or
# stale record blocks; a failed nightly only banners, as the first and last line and atop the summary.
record="${XDG_STATE_HOME:-$HOME/.local/state}/mcp-gateway/first-paint/nightly.json"
export FIRST_PAINT_BANNER=""
case "$mode" in ready | proof | verdicts)
	check=$(cd ui-tests && RECORD="$record" node --input-type=module -e "
import { existsSync, readFileSync } from 'node:fs';
import { nightlyCheck } from './perf/first-paint-lib.mjs';
const r = existsSync(process.env.RECORD) ? JSON.parse(readFileSync(process.env.RECORD, 'utf8')) : null;
const n = nightlyCheck(r, Date.now());
console.log(n.ok ? (n.banner ?? '') : 'MISSED ' + n.problem);
console.log(r ? 'last nightly: ' + r.timestamp + ' on ' + r.ref + ' ' + r.sha + ' (exit ' + r.exit + ')' : 'last nightly: none');
") || exit 2
	verdict=$(sed -n 1p <<<"$check")
	if [ "${verdict#MISSED }" != "$verdict" ]; then
		echo "${verdict#MISSED }"
		echo "run the nightly by hand: ui-tests/perf/first-paint-nightly.sh <dedicated worktree> [branch]"
		echo "exit 2: fault"
		exit 2
	fi
	FIRST_PAINT_BANNER=$verdict
	[ -n "$FIRST_PAINT_BANNER" ] && echo "$FIRST_PAINT_BANNER"
	sed -n 2p <<<"$check"
	;;
esac
finish() {
	[ -n "$FIRST_PAINT_BANNER" ] && echo "$FIRST_PAINT_BANNER"
	exit "$1"
}

deadline=$(($(date +%s) + 6 * 3600))
dropped=0
while :; do
	spark-slot run full "$owner" "first-paint-$mode" -- ui-tests/perf/first-paint-launch.sh "$mode" "$sha"
	rc=$?
	if [ "$rc" -eq 75 ] && [ "$dropped" -eq 0 ]; then dropped=1; echo "Spark unreachable once (75); retrying"; continue; fi
	[ "$rc" -eq 3 ] || finish "$rc"
	if [ $(($(date +%s) + 900)) -gt "$deadline" ]; then echo "no quiet window found in 6 hours (exit 3)"; finish 3; fi
	echo "busy host (exit 3) at $(date -u +%H:%MZ); retrying in 15 minutes"
	sleep 900
done
