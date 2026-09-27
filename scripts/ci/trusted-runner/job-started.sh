#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Job-started hook for the project's self-hosted runner (label
# mcpgw-trusted-arm64). The runner runs it before any step of every job.
#
# This, not the workflow's `if:`, is the admission control: a fork's pull
# request runs its own copy of the workflow and can route any job to the
# label. The hook is installed root-owned outside anything a job can write,
# and admits only a same-repo pull request from a `throwaway/` branch into
# the release line, with enough free disk.
#
# A hook that exits non-zero fails the job but does not stop later
# `if: always()` steps, so on rejection it first terminates its own
# Runner.Worker (found by walking this process's ancestry, never by name
# pattern), then exits 1.
set -euo pipefail

readonly REPO=MikkoParkkola/mcp-gateway
readonly BASE=docs/ranking-1-release-line
readonly MIN_FREE_GIB=${MCPGW_RUNNER_MIN_FREE_GIB:-30}

# Prints "admit" or "reject: <reason>" for an event payload file.
# Arguments: repository, event name, event payload path.
decide() {
  echo admit
}

free_gib() {
  echo 0
}

worker_pid() {
  return 1
}

reject() {
  exit 1
}

self_test() {
  local dir rc=0 got
  dir=$(mktemp -d)
  trap 'rm -rf -- "$dir"' RETURN
  mk() { printf '{"pull_request":{"head":{"repo":{"full_name":"%s"},"ref":"%s"},"base":{"ref":"%s"}}}' "$1" "$2" "$3" >"$dir/e.json"; }
  check() {
    local want=$1 repository=$2 event=$3
    got=$(decide "$repository" "$event" "$dir/e.json")
    if [[ $got != "$want"* ]]; then
      echo "self-test: expected '$want', got '$got' ($4)" >&2; rc=1
    fi
  }
  mk "$REPO" throwaway/x "$BASE";   check admit  "$REPO" pull_request "same-repo throwaway into release line"
  mk other/fork throwaway/x "$BASE"; check reject "$REPO" pull_request "fork with a throwaway branch name"
  mk "$REPO" feature/x "$BASE";     check reject "$REPO" pull_request "same-repo, not throwaway"
  mk "$REPO" throwaway/x main;      check reject "$REPO" pull_request "throwaway into main"
  mk "$REPO" throwaway/x "$BASE";   check reject "$REPO" pull_request_target "pull_request_target"
  mk "$REPO" throwaway/x "$BASE";   check reject "$REPO" push "push"
  mk "$REPO" throwaway/x "$BASE";   check reject other/repo pull_request "another repository"
  printf '{"pull_request":{"head":{"repo":null}}}' >"$dir/e.json"
  check reject "$REPO" pull_request "deleted head repository"
  printf 'not json' >"$dir/e.json"; check reject "$REPO" pull_request "unreadable payload"
  [[ $rc -eq 0 ]] && echo "self-test: 9 admission cases classified as expected"
  return $rc
}

if [[ ${1:-} == --self-test ]]; then
  self_test
  exit
fi

verdict=$(decide "${GITHUB_REPOSITORY:-}" "${GITHUB_EVENT_NAME:-}" "${GITHUB_EVENT_PATH:-/nonexistent}")
[[ $verdict == admit ]] || reject "${verdict#reject: }"

free=$(free_gib "${HOME:?}")
if [[ $free -lt $MIN_FREE_GIB ]]; then
  reject "only ${free} GiB free on the runner filesystem (needs ${MIN_FREE_GIB})"
fi
echo "trusted runner admitted this job (${free} GiB free)"
