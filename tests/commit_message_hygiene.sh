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
  git -C "$repo" commit -q -m "$message"

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

if (( failures > 0 )); then
  printf 'Commit message hygiene fixtures failed: %d case(s).\n' "$failures" >&2
  exit 1
fi

printf 'Commit message hygiene fixtures OK.\n'
