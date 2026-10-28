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

# An info marker is not the pronoun; a parenthesised aside in first person is.
run_case info_marker_is_not_a_pronoun pass 'feat(ui): tooltip trigger

- The (i) trigger is a button named after its title'

run_case first_person_in_parentheses fail 'fix(router): drop the retry

- Remove the second attempt (I checked every caller)'

run_case capital_pronoun_in_parentheses fail 'fix(router): drop the retry

- (I) checked every caller before removing it'

# A pagination cursor is a code noun; the editor of that name is a tool.
run_case pagination_cursor_is_not_a_tool pass 'feat(api): page through the event list

- Return the next page cursor with each response'

run_case cursor_editor_names_tool fail 'fix(router): reject a credential-bearing URL

- Apply the fix Cursor suggested'

run_case lowercase_cursor_attribution fail 'fix(router): reject a credential-bearing URL

- Apply cursor'"'"'s suggested fix'

run_case lowercase_cursor_ide fail 'fix(router): reject a credential-bearing URL

- Generated in the cursor IDE'

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

run_case acceptance_criterion_id_after_cutoff pass 'test(router): cover the loopback refusal

- Pin MIK-1234.ROUTE.1 with a unit test'

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
# A reviewer model named in a message, in any spelling; the attribution
# trailer names the authoring tool and stays allowed.
run_case reviewer_gpt_seat fail 'fix(config): apply the gpt-review finding'
run_case reviewer_muse fail 'fix(config): what muse asked for'
run_case reviewer_glm fail 'test(config): the GLM row'
run_case reviewer_review_model fail 'docs: both review models agreed'
run_case attribution_trailer_only pass 'fix(router): refuse a credentialed http URL

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
run_case word_containing_a_name pass 'docs: the amused operator ran glmark'
run_case reviewer_in_a_trailer fail 'fix(router): refuse a credentialed http URL

Reviewed-by: gpt-5.5'

# A merge commit's message is checked too.
merge_case() {
  local name="$1" expectation="$2" message="$3" repo="$tmp_root/merge_$1" status=0
  mkdir -p "$repo"
  git -C "$repo" init -q
  git -C "$repo" config user.email "test@localhost"
  git -C "$repo" config user.name "Commit Hygiene Test"
  printf 'base\n' >"$repo/file.txt"
  git -C "$repo" add file.txt
  git -C "$repo" commit -q -m "chore: seed the fixture"
  git -C "$repo" checkout -q -b side
  printf 'side\n' >"$repo/side.txt"
  git -C "$repo" add side.txt
  git -C "$repo" commit -q -m "chore: a side change"
  git -C "$repo" checkout -q -
  GIT_AUTHOR_DATE=2030-01-01T00:00:00Z GIT_COMMITTER_DATE=2030-01-01T00:00:00Z \
    git -C "$repo" merge -q --no-ff -m "$message" side
  (cd "$repo" && bash "$checker" 'HEAD~1..HEAD' >/dev/null 2>&1) || status=$?
  if [[ "$expectation" == "fail" && "$status" -eq 0 ]]; then
    printf 'FAIL %s: expected the checker to reject this merge message\n' "$name" >&2
    failures=$((failures + 1))
  elif [[ "$expectation" == "pass" && "$status" -ne 0 ]]; then
    printf 'FAIL %s: expected a clean merge message to pass, exit %d\n' "$name" "$status" >&2
    failures=$((failures + 1))
  fi
}
merge_case merge_naming_a_reviewer fail 'Merge the base after the muse review'
merge_case merge_clean pass 'Merge the release line'

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
# An explicitly empty body (PR_BODY set to "") passes: it cannot leak
# anything, and CI always sets the variable. No body at all (PR_BODY unset,
# no file) is a misused call, refused rather than read as empty and clean.
pr_body_case empty_body pass ''
pr_body_unset_case() {
  local status=0
  env -u PR_BODY bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" >/dev/null 2>&1 || status=$?
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL pr_body_unset: expected the checker to refuse a call with no body\n' >&2
    failures=$((failures + 1))
  fi
}
pr_body_unset_case

# The body may come from a file instead of $PR_BODY; a misused call is refused
# rather than read as an empty, clean body.
pr_body_args_case() {
  local name="$1" expectation="$2" body="$3"
  shift 3
  local status=0
  if [[ -n "$body" ]]; then
    PR_BODY="$body" bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" "$@" >/dev/null 2>&1 || status=$?
  else
    env -u PR_BODY bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" "$@" >/dev/null 2>&1 || status=$?
  fi
  if [[ "$expectation" == "pass" && "$status" -ne 0 ]]; then
    printf 'FAIL pr_body_%s: expected pass, exit %d\n' "$name" "$status" >&2
    failures=$((failures + 1))
  elif [[ "$expectation" == "fail" && "$status" -eq 0 ]]; then
    printf 'FAIL pr_body_%s: expected the checker to refuse\n' "$name" >&2
    failures=$((failures + 1))
  fi
}
body_dir="$tmp_root/pr-bodies"
mkdir -p "$body_dir"
printf '## Summary\n\n- Refuse a stale handle\n' >"$body_dir/clean.md"
printf 'Refs MIK-1234\n' >"$body_dir/ticket.md"
: >"$body_dir/empty.md"
pr_body_args_case file_clean pass '' "$body_dir/clean.md"
pr_body_args_case file_with_ticket_id fail '' "$body_dir/ticket.md"
pr_body_args_case file_empty pass '' "$body_dir/empty.md"
pr_body_args_case file_missing fail '' "$body_dir/absent.md"
pr_body_args_case unknown_option fail 'Fine body.' --body
pr_body_args_case two_files fail '' "$body_dir/clean.md" "$body_dir/ticket.md"
pr_body_args_case file_and_env_both_given fail 'Fine body.' "$body_dir/clean.md"
pr_body_case acceptance_criterion_id pass 'Covers MIK-9999.HANDLE.1 and MIK-9999.HANDLE.2a.'
pr_body_case acceptance_id_beside_a_citation fail 'Covers MIK-9999.HANDLE.1, see MIK-9999.'

# Reviewer models are internal process: a public body or title never names
# one. The attribution footer names the authoring tool and stays allowed.
pr_body_case attribution_footer pass '🤖 Generated with [Claude Code](https://claude.com/claude-code)'
pr_body_case gpt_seat fail 'Reviews: gpt-review SHIP at the head.'
pr_body_case gpt_version fail 'Reviewed by gpt-5.5.'
pr_body_case muse fail 'The second seat (muse) said SHIP.'
pr_body_case glm fail 'GLM-5.3 asked for one more row.'
pr_body_case grok fail 'grok found nothing.'
pr_body_case kimi fail 'Kimi raised a LOW finding.'
pr_body_case codex fail 'A codex run returned no verdict.'
pr_body_case review_model fail 'Two review models agreed.'
pr_body_case word_containing_a_name pass 'The amused operator ran glmark and gptables.'
pr_body_case chatgpt fail 'ChatGPT agreed.'
pr_body_case compact_version fail 'GPT5 found one issue.'
pr_body_case footer_naming_another_tool pass '🤖 Generated with [Codex](https://openai.com/codex)'
pr_body_case footer_with_a_reviewer_appended fail '🤖 Generated with [Claude Code](https://claude.com/claude-code), reviewed by GPT5'
pr_body_case compact_version_with_suffix fail 'GPT4o found one issue.'

# The refusal names the matched word, never the rest of the line.
pr_body_echo_case() {
  local output status=0
  output="$(PR_BODY="$1" bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" 2>&1)" || status=$?
  if [[ "$status" -eq 0 || "$output" == *"$2"* ]]; then
    printf 'FAIL pr_body_no_echo: exit %d, output: %s\n' "$status" "$output" >&2
    failures=$((failures + 1))
  fi
}
pr_body_echo_case 'codex said token-S3CRET-VALUE is fine' 'token-S3CRET-VALUE'

# The title is held to the same rule (PR_TITLE beside PR_BODY, as CI passes it).
pr_title_case() {
  local name="$1" expectation="$2" title="$3" status=0
  PR_BODY='A clean body.' PR_TITLE="$title" bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" >/dev/null 2>&1 || status=$?
  if [[ "$expectation" == "pass" && "$status" -ne 0 ]]; then
    printf 'FAIL pr_title_%s: expected a clean title to pass, exit %d\n' "$name" "$status" >&2
    failures=$((failures + 1))
  elif [[ "$expectation" == "fail" && "$status" -eq 0 ]]; then
    printf 'FAIL pr_title_%s: expected the checker to reject this title\n' "$name" >&2
    failures=$((failures + 1))
  fi
}
pr_title_case names_a_model fail 'fix(config): apply the muse review'
pr_title_case clean pass 'fix(config): refuse a write it cannot make in place'
pr_title_case ticket_id fail 'fix(config): close MIK-1234'

# An empty body still has its title checked.
pr_empty_body_title_case() {
  local name="$1" body="$2" status=0
  PR_BODY="$body" PR_TITLE='fix(config): apply the muse review' bash "$source_repo/scripts/dev/check-pr-body-hygiene.sh" >/dev/null 2>&1 || status=$?
  if [[ "$status" -eq 0 ]]; then
    printf 'FAIL pr_title_%s: a banned title passed with an empty body\n' "$name" >&2
    failures=$((failures + 1))
  fi
}
pr_empty_body_title_case with_empty_body ''
pr_empty_body_title_case with_blank_body $'  \n\t\n'


if (( failures > 0 )); then
  printf 'Commit message hygiene fixtures failed: %d case(s).\n' "$failures" >&2
  exit 1
fi

printf 'Commit message hygiene fixtures OK.\n'
