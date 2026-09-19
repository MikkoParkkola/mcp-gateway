#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Guard what the published history says. A commit message states facts about
# the code; it never narrates the authoring session, names the tool that wrote
# it, or apologises. Every message in this repository is world-readable.
set -euo pipefail

range="${1:-}"
if [[ -z "$range" ]]; then
  upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
  if [[ -n "$upstream" ]]; then
    range="$upstream..HEAD"
  else
    range="origin/main..HEAD"
  fi
fi

# Each entry is <pattern>::<reason>, split on the first "::" so an alternation
# inside the pattern stays intact. Patterns are extended regular expressions
# matched case-insensitively against the message with trailers removed, so a
# Co-Authored-By line naming a model is not a hit.
checks=(
  "\\b(i|i'm|i've|my|mine)\\b::first person: state facts about the code, not about the author"
  "\\bwe (added|fixed|caught|found|decided|realised|realized)\\b::first person: describe the change, not the people who made it"
  "\\b(sub-?agent|agent session|scratchpad|worktree)\\b::authoring-process narration"
  "\\b(claude|codex|kimi|chatgpt|gpt-[0-9]|grok|copilot|cursor)\\b::names the authoring tool as an actor"
  "\\b(this session|the session transcript|earlier turn|compaction|context window)\\b::session narration"
  "\\b(review seat|the operator|the reviewer (said|asked|caught)|per the ruling|ruling [0-9])\\b::internal process shorthand"
  "\\b(sorry|oops|apolog(y|ies|ise|ize)|my (mistake|bad|earlier) )::apology or self-criticism"
  "\\b(as (you|the user) (asked|requested)|as instructed)\\b::addresses a reader who is not there"
  "\\bTODO\\b::unfinished marker in published history"
)

failures=0
commits="$(git rev-list --no-merges "$range" 2>/dev/null || true)"
[[ -n "$commits" ]] || { printf 'Commit message hygiene OK: no commits in %s.\n' "$range"; exit 0; }

while IFS= read -r sha; do
  [[ -n "$sha" ]] || continue
  # Drop trailer lines: they legitimately carry names and addresses. Drop the
  # I/O token too, or the acronym reads as the first-person pronoun.
  body="$(git log -1 --format='%B' "$sha" |
    sed -E '/^[A-Za-z-]+-[Bb]y:[[:space:]]/d; /^(Signed-off-by|Refs|Fixes|Closes|Reviewed-on):[[:space:]]/d' |
    sed -E 's#I/O#IO#g')"

  # The forge appends " (#123)" when it squashes, so the ceiling governs what
  # the author wrote.
  subject="$(git log -1 --format='%s' "$sha" | sed -E 's/ \(#[0-9]+\)$//')"
  if (( ${#subject} > 72 )); then
    printf 'FAIL %s: subject is %d characters, ceiling is 72\n' "${sha:0:8}" "${#subject}" >&2
    failures=$((failures + 1))
  fi

  for check in "${checks[@]}"; do
    pattern="${check%%::*}"
    reason="${check#*::}"
    if match="$(printf '%s\n' "$body" | grep -E -i -n -m 1 "$pattern" || true)"; [[ -n "$match" ]]; then
      printf 'FAIL %s: %s -- %s\n' "${sha:0:8}" "$reason" "$match" >&2
      failures=$((failures + 1))
    fi
  done
done <<<"$commits"

if (( failures > 0 )); then
  printf '\nCommit message hygiene failed with %d issue(s) in %s.\n' "$failures" "$range" >&2
  printf 'Rewrite the message with git commit --amend or git rebase -i. State what the\n' >&2
  printf 'code does; put evidence and reasoning in the pull request body instead.\n' >&2
  exit 1
fi

printf 'Commit message hygiene OK: %d commit(s) in %s.\n' "$(printf '%s\n' "$commits" | wc -l | tr -d ' ')" "$range"
