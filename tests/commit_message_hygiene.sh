#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

source_repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$source_repo/scripts/dev/check-commit-message-hygiene.sh"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

failures=0

# One commit carrying $1 as its message, checked over its own single-commit range.
run_case() {
  local name="$1" expectation="$2" message="$3"
  # Author and committer dates of the checked commit; both default to after
  # the tracker-id cutoff, so every rule applies.
  local authored="${4:-2030-01-01T00:00:00Z}" committed="${5:-2030-01-01T00:00:00Z}"
  local repo="$tmp_root/$name"
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Commit Hygiene Test"
  printf 'base\n' >"$repo/file.txt"
  git -C "$repo" add file.txt
  git -C "$repo" commit -q -m "chore: seed the fixture"
  printf 'change\n' >>"$repo/file.txt"
  git -C "$repo" add file.txt
  GIT_AUTHOR_DATE="$authored" GIT_COMMITTER_DATE="$committed" git -C "$repo" commit -q -m "$message"

  local status=0
  (cd "$repo" && bash "$checker" 'HEAD~1..HEAD' >/dev/null 2>&1) || status=$?

  if [[ "$expectation" == "pass" && "$status" -ne 0 ]]; then
    printf 'FAIL %s: expected a clean message to pass, exit %d\n' "$name" "$status" >&2
    failures=$((failures + 1))
  elif [[ "$expectation" == "fail" && "$status" -eq 0 ]]; then
    printf 'FAIL %s: expected the checker to reject this message\n' "$name" >&2
    failures=$((failures + 1))
  fi
}

run_case clean pass 'fix(router): reject a backend URL carrying credentials over plain http

- Refuse the connection unless the host is loopback
- Cover the refusal with a unit test

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>'

run_case first_person fail 'fix(router): reject a credential-bearing URL

- I moved the check into the shared helper'

run_case names_tool fail 'fix(router): reject a credential-bearing URL

- Apply the fix Claude Code suggested'

run_case session_narration fail 'fix(router): reject a credential-bearing URL

- Restore the guard dropped earlier in this session'

run_case process_shorthand fail 'fix(router): reject a credential-bearing URL

- Close the row the reviewer asked about per the ruling'

run_case apology fail 'fix(router): reject a credential-bearing URL

- Sorry, my earlier patch missed the loopback case'

run_case long_subject fail 'fix(router): reject every backend URL that carries credentials over plain http because the transport cannot protect them'

run_case io_acronym_is_not_first_person pass 'perf(stdio): add a backend fixture with no per-call I/O

- Serve the fixture from memory so the benchmark measures the router'

run_case squash_suffix_does_not_break_the_ceiling pass 'fix(meta-mcp): replay an uncertain side effect as indeterminate (#597)

- Settle the reservation with the uncertainty marker'

run_case trailer_is_not_a_hit pass 'docs(readme): state the supported protocol revisions

- List every revision the gateway negotiates

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Signed-off-by: Mikko Parkkola <mikko@example.com>'

run_case ticket_id_in_body fail 'fix(router): reject a credential-bearing URL

- Close the gap from MIK-1234'

run_case ticket_id_in_trailer fail 'fix(router): reject a credential-bearing URL

- Refuse the connection unless the host is loopback

Refs: MIK-1234'

# A backport cherry-picked after the cutoff keeps its old author date, so its
# message is still recognised as old.
run_case ticket_id_authored_before_cutoff_picked_after pass 'fix(router): reject a credential-bearing URL

- Close the gap from MIK-1234' '2026-01-01T00:00:00Z' '2030-01-01T00:00:00Z'

run_case ticket_id_authored_after_cutoff fail 'fix(router): reject a credential-bearing URL

- Close the gap from MIK-1234' '2030-01-01T00:00:00Z' '2030-01-01T00:00:00Z'

run_case private_project fail 'fix(router): reject a credential-bearing URL

- Match the hebb client behaviour'

run_case home_path fail 'fix(router): reject a credential-bearing URL

- Read the fixture from /Users/mikko/github/mcp-gateway/tests'

run_case agent_config_path fail 'fix(router): reject a credential-bearing URL

- Mirror the guard in ~/.claude/hooks'

run_case private_address fail 'fix(router): reject a credential-bearing URL

- Point the smoke test at 100.101.102.103'

# A merge commit and a co-author line are read too.
merge_case() {
  local repo="$tmp_root/merge_with_ticket_id" status=0
  mkdir -p "$repo"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Commit Hygiene Test"
  printf 'base\n' >"$repo/file.txt"
  git -C "$repo" add file.txt
  git -C "$repo" commit -q -m "chore: seed the fixture"
  git -C "$repo" checkout -q -b side
  printf 'side\n' >"$repo/side.txt"
  git -C "$repo" add side.txt
  git -C "$repo" commit -q -m "feat: add the side file"
  git -C "$repo" checkout -q main
  GIT_AUTHOR_DATE=2030-01-01T00:00:00Z git -C "$repo" merge -q --no-ff side -m "Merge the side branch for MIK-1234"
  (cd "$repo" && bash "$checker" 'HEAD~1..HEAD' >/dev/null 2>&1) || status=$?
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL merge_with_ticket_id: expected the checker to reject a merge citing a tracker id\n' >&2
    failures=$((failures + 1))
  fi
}
merge_case

run_case private_name_in_coauthor fail 'fix(router): reject a credential-bearing URL

- Refuse the connection unless the host is loopback

Co-Authored-By: Hebb Agent <agent@example.com>'

# The pull-request body check reads $PR_BODY.
pr_body_case() {
  local name="$1" expectation="$2" body="$3" status=0
  PR_BODY="$body" bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" >/dev/null 2>&1 || status=$?
  if [[ "$expectation" == "pass" && "$status" -ne 0 ]]; then
    printf 'FAIL pr_body_%s: expected a clean body to pass, exit %d\n' "$name" "$status" >&2
    failures=$((failures + 1))
  elif [[ "$expectation" == "fail" && "$status" -eq 0 ]]; then
    printf 'FAIL pr_body_%s: expected the checker to reject this body\n' "$name" >&2
    failures=$((failures + 1))
  fi
}

pr_body_case clean pass '## Summary

- Refuse a credential-bearing URL over plain http
- Credit: thanks to @terafin for the report; contact mikko.parkkola@iki.fi'
pr_body_case ticket_id fail 'Closes MIK-1234'
pr_body_case private_project fail 'Same shape as the botnaut client.'
pr_body_case camel_identifier fail 'Renames HebbBridgeConfig.'
pr_body_case home_path fail 'Built in /Users/mikko/github/mcp-gateway.'
pr_body_case agent_config fail 'See $HOME/.claude/rules for the gate.'
pr_body_case private_address fail 'Measured against 100.64.1.2.'
pr_body_case learning_rule_is_not_a_name pass 'Uses a Hebbian decay for ranking.'
pr_body_case empty_body pass ''

if (( failures > 0 )); then
  printf 'Commit message hygiene fixtures failed: %d case(s).\n' "$failures" >&2
  exit 1
fi

printf 'Commit message hygiene fixtures OK.\n'
