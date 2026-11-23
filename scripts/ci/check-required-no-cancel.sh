#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# The repository ruleset requires the check "Public repo hygiene (base checker)" on main and the
# release line. Its workflow must never cancel one of its own runs: two events at one pull request
# head (marking it ready and editing its body) start two runs, a concurrency group cancels one, and
# the ruleset reads that cancelled run under the required name and refuses the merge. Without a
# concurrency group every run completes; two runs at one head judge the same tree and agree.
#
# Fails when the workflow declares a concurrency group anywhere (workflow or job level): even
# without cancel-in-progress, GitHub cancels a pending run when a newer one joins its group.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/hygiene-base.yml"

# Prints the offending lines of $1 (a `concurrency:` or `cancel-in-progress:` key at any indent).
offending() { grep -nE '^[[:space:]]*(concurrency|cancel-in-progress)[[:space:]]*:' "$1" || true; }

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  printf 'on: pull_request_target\nconcurrency:\n  group: g\n  cancel-in-progress: true\njobs: {}\n' >"$tmp/top.yml"
  printf 'on: pull_request_target\nconcurrency:\n  group: g\njobs: {}\n' >"$tmp/no-cancel-key.yml"
  printf 'on: pull_request_target\njobs:\n  j:\n    concurrency: g\n    runs-on: ubuntu-latest\n' >"$tmp/job.yml"
  printf 'on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo concurrency is fine in text\n' >"$tmp/clean.yml"
  for f in top no-cancel-key job; do
    if [ -z "$(offending "$tmp/$f.yml")" ]; then echo "self-test: $f.yml was not caught" >&2; exit 1; fi
  done
  if [ -n "$(offending "$tmp/clean.yml")" ]; then echo "self-test: clean.yml was flagged" >&2; exit 1; fi
  echo "self-test: a workflow-level group, a group without cancel-in-progress and a job-level group are caught; a clean file passes"
  exit 0
fi

[ -f "$WORKFLOW" ] || { echo "$WORKFLOW is missing" >&2; exit 1; }
bad="$(offending "$WORKFLOW")"
if [ -n "$bad" ]; then
  echo "$WORKFLOW must not declare a concurrency group: a cancelled run of a required check blocks merges." >&2
  printf '%s\n' "$bad" >&2
  exit 1
fi
echo "$WORKFLOW declares no concurrency group: none of its runs is ever cancelled by another"
