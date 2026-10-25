#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Guard what a pull request body says. The body is world-readable the moment
# it is posted, so it is held to the same private-content patterns as the
# tracked tree, and may not cite a tracker id.
#
#   PR_BODY="$(gh pr view N --json body -q .body)" scripts/dev/check-pr-body-hygiene.sh
#
# CI passes the body through the environment, never by interpolating it into
# the script, so the body is data and cannot become shell.
set -euo pipefail

# shellcheck source=scripts/dev/public-hygiene-patterns.sh
source "$(dirname "${BASH_SOURCE[0]}")/public-hygiene-patterns.sh"

body="${PR_BODY-}"
failures=0

report() {
  printf 'FAIL: pull request body line %s %s\n' "$1" "$2" >&2
  failures=$((failures + 1))
}

n=0
while IFS= read -r line || [[ -n "$line" ]]; do
  n=$((n + 1))
  for check in "${private_content_checks[@]}"; do
    id="${check%%::*}"
    rest="${check#*::}"
    flags="${rest%%::*}"
    rest="${rest#*::}"
    regex="${rest%%::*}"
    reason="${rest#*::}"
    if [[ "$flags" == i ]]; then
      shopt -s nocasematch
    fi
    if [[ "$line" =~ $regex ]]; then
      report "$n" "$reason ($id): ${BASH_REMATCH[0]}"
    fi
    shopt -u nocasematch
  done
  bare="$line"
  while [[ "$bare" =~ $ac_id_regex ]]; do bare="${bare/"${BASH_REMATCH[0]}"/}"; done
  if [[ "$bare" =~ $ticket_id_regex ]]; then
    report "$n" "cites a tracker id: ${BASH_REMATCH[0]}"
  fi
done <<<"$body"

if (( failures > 0 )); then
  printf 'Pull request body hygiene failed with %d issue(s). Edit the body; the check reruns on edit.\n' "$failures" >&2
  exit 1
fi
printf 'Pull request body hygiene OK.\n'
