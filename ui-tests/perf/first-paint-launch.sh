#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Mac side of the first-paint gate, one attempt. Run it inside a full Spark slot, from the tree to judge
# (spark-slot runs jobs from a detached snapshot of the worktree, which has git):
#   spark-slot run full <owner> first-paint -- ui-tests/perf/first-paint-launch.sh <mode> <sha>
# It checks the tree is clean at <sha> (Spark gets no .git), sends it to Spark, and runs the gate there under a
# Spark-local lock: a second gate finds the lock held and exits 3 at once. Outputs, and a calibration's config,
# are copied back to ~/.claude/data/first-paint/.
set -uo pipefail
mode=${1:?mode} sha=${2:?sha}
root=$(git rev-parse --show-toplevel) || exit 2
problem=$(cd "$root/ui-tests" && HEAD_SHA=$(git rev-parse HEAD) PORCELAIN=$(git status --porcelain) EXPECTED=$sha node --input-type=module -e "
import { treeCheck } from './perf/first-paint-lib.mjs';
const p = treeCheck({ head: process.env.HEAD_SHA, expected: process.env.EXPECTED, porcelain: process.env.PORCELAIN });
if (p) console.log(p);") || exit 2
if [ -n "$problem" ]; then echo "fault: $problem"; echo "exit 2: fault"; exit 2; fi

ssh_cmd=(ssh -o IdentityAgent=none -i "$HOME/.ssh/id_ed25519_spark" -o BatchMode=yes
	-o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=20 spark)
remote='set -uo pipefail
h=~/first-paint; mkdir -p "$h"
exec 9>"$h/gate.lock"
flock -n 9 || { echo "another first-paint gate holds the lock"; echo "exit 3: busy host, not judged"; exit 3; }
rm -rf "$h/src.new"; mkdir -p "$h/src.new" "$h/src"; tar -xz -C "$h/src.new" || exit 2
rsync -rlpc --delete --exclude /ui-tests/node_modules "$h/src.new/" "$h/src/" && rm -rf "$h/src.new" || exit 2
cd "$h/src/ui-tests" || exit 2
want=$(sha256sum package-lock.json | cut -d" " -f1)
if [ "$(cat "$h/lock.sha" 2>/dev/null)" != "$want" ]; then
  npm ci --ignore-scripts --no-audit --no-fund >"$h/npm-ci.log" 2>&1 || { echo "fault: npm ci failed, see $h/npm-ci.log"; exit 2; }
  echo "$want" >"$h/lock.sha"
fi
node perf/first-paint.mjs --mode="$1" --sha="$2"'

out=$(mktemp); trap 'rm -f "$out"' EXIT
COPYFILE_DISABLE=1 tar -C "$root" --no-xattrs --no-mac-metadata --exclude .git --exclude target --exclude node_modules -czf - . |
	"${ssh_cmd[@]}" "bash -c $(printf %q "$remote") _ $mode $sha" | tee "$out"
rc=${PIPESTATUS[1]}
[ "$rc" -eq 255 ] && { echo "could not reach Spark over ssh"; exit 75; }

dest=~/.claude/data/first-paint; mkdir -p "$dest/out"
name=$(sed -n 's/^outputs: \(.*\)\.json, .*/\1/p' "$out" | tail -1)
if [ -n "$name" ]; then "${ssh_cmd[@]}" "cat $name.json" >"$dest/out/${name##*/}.json"; "${ssh_cmd[@]}" "cat $name.md" >"$dest/out/${name##*/}.md"; fi
if [ "$mode" = calibrate ] && [ "$rc" -eq 0 ]; then
	"${ssh_cmd[@]}" 'cat ~/first-paint/src/ui-tests/perf/first-paint.config.json' >"$dest/first-paint.config.json"
	echo "config copied to $dest/first-paint.config.json (commit it as a reviewed change)"
fi
exit "$rc"
