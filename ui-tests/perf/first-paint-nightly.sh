#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# The nightly first-paint gate. launchd (com.claude.mcp-gateway.first-paint-nightly, 03:30) runs an
# installed copy of this file, so moving the worktree cannot change the script under it:
#   first-paint-nightly.sh <dedicated worktree> <branch to measure>
# Fetches the branch into a private ref (refs/first-paint/nightly; nobody's origin/* refs move), checks the
# worktree out detached there, runs the gate in nightly mode under the first-paint slot owner, and records
# timestamp, branch, SHA and exit in ~/.claude/data/first-paint/nightly.json whatever happened, so READY can
# tell a missed nightly from a failed one. Start it by hand with:
#   launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway.first-paint-nightly
{
	set -uo pipefail
	wt=${1:?worktree} branch=${2:?branch}
	dir=~/.claude/data/first-paint
	mkdir -p "$dir"
	sha=none rc=2
	echo "nightly $(date -u +%Y-%m-%dT%H:%M:%SZ): $branch in $wt"
	if cd "$wt" && git fetch -q origin "+refs/heads/$branch:refs/first-paint/nightly" && git checkout -q --detach refs/first-paint/nightly; then
		sha=$(git rev-parse HEAD)
		if [ -x ui-tests/perf/first-paint-gate.sh ]; then
			ui-tests/perf/first-paint-gate.sh nightly "$sha" first-paint
			rc=$?
		else
			echo "no first-paint gate in $branch at $sha"
		fi
	else
		echo "could not move $wt to $branch"
	fi
	printf '{"timestamp":"%s","ref":"%s","sha":"%s","exit":%d}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$branch" "$sha" "$rc" >"$dir/nightly.json.new" &&
		mv "$dir/nightly.json.new" "$dir/nightly.json"
	echo "nightly exit $rc"
	exit "$rc"
}
