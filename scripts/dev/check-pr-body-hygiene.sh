#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Guard what a pull request body says. The body is world-readable the moment
# it is posted, so it is held to the same private-content patterns as the
# tracked tree, may not cite a tracker id, and may not name the AI models that
# reviewed the change (internal process; the attribution footer, which names
# the authoring tool, is allowed). The title, given in PR_TITLE, is held to
# the same rules.
#
#   PR_BODY="$(gh pr view N --json body -q .body)" scripts/dev/check-pr-body-hygiene.sh
#   PR_TITLE="$(gh pr view N --json title -q .title)" PR_BODY=... scripts/dev/check-pr-body-hygiene.sh
#   scripts/dev/check-pr-body-hygiene.sh body.md
#
# Exactly one source: $PR_BODY or one file. Whether PR_BODY is SET decides,
# not its value: set to "" is an explicit empty body, which passes (it cannot
# leak anything, and CI always sets it), though the title is still checked. Unset with no file, two sources, a
# missing file, more than one file or an option is a misused call and is
# refused, because a check that reads nothing and prints OK is worse than no
# check.
#
# CI passes the body through the environment, never by interpolating it into
# the script, so the body is data and cannot become shell.
set -euo pipefail

# shellcheck source=scripts/dev/public-hygiene-patterns.sh
source "$(dirname "${BASH_SOURCE[0]}")/public-hygiene-patterns.sh"

usage() {
  printf 'usage: PR_BODY=<text> %s  |  %s <file>\n' "$0" "$0" >&2
  exit 2
}
if (( $# > 1 )) || [[ "${1:-}" == -* ]]; then
  usage
fi
if (( $# == 1 )); then
  [[ -z "${PR_BODY+set}" ]] || { printf 'check-pr-body-hygiene: give the body in PR_BODY or a file, not both\n' >&2; exit 2; }
  [[ -f "$1" ]] || { printf 'check-pr-body-hygiene: no such file: %s\n' "$1" >&2; exit 2; }
  body="$(cat -- "$1")"
elif [[ -n "${PR_BODY+set}" ]]; then
  body="$PR_BODY"
else
  usage
fi
failures=0

report() {
  printf 'FAIL: pull request %s %s\n' "$1" "$2" >&2
  failures=$((failures + 1))
}

check_line() {
  local where="$1" line="$2"
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
      report "$where" "$reason ($id): ${BASH_REMATCH[0]}"
    fi
    shopt -u nocasematch
  done
  shopt -s nocasematch
  if [[ ! "$line" =~ $authoring_footer_regex && "$line" =~ $reviewer_regex ]]; then
    report "$where" "names a reviewing model: ${BASH_REMATCH[2]}"
  fi
  shopt -u nocasematch
  bare="$line"
  while [[ "$bare" =~ $ac_id_regex ]]; do bare="${bare/"${BASH_REMATCH[0]}"/}"; done
  if [[ "$bare" =~ $ticket_id_regex ]]; then
    report "$where" "cites a tracker id: ${BASH_REMATCH[0]}"
  fi
}

if [[ -n "${PR_TITLE:-}" ]]; then
  check_line "title" "$PR_TITLE"
fi
if [[ -n "${body//[[:space:]]/}" ]]; then
  n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    check_line "body line $n" "$line"
  done <<<"$body"
fi

if (( failures > 0 )); then
  printf 'Pull request body hygiene failed with %d issue(s). Edit the title or body; the check reruns on edit.\n' "$failures" >&2
  exit 1
fi
printf 'Pull request body hygiene OK.\n'
