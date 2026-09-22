#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Guard what the published history says. A commit message states facts about
# the code; it never narrates the authoring session, names the tool that wrote
# it, or apologises. Every message in this repository is world-readable.
#
# WHAT IS REJECTED, as a quick reference -- the authoritative list is `checks`
# below, and reading it before writing a message is cheaper than a rejection:
#
#   * first person: i, i'm, i've, my, mine; we added/fixed/caught/found/
#     decided/realised/realized
#   * authoring process: sub-agent, agent session, scratchpad, worktree
#   * the tool as an actor: any assistant or model name
#   * session narration: this session, the session transcript, earlier turn,
#     compaction, context window
#   * internal shorthand: review seat, the operator, the reviewer said/asked/
#     caught, per the ruling, ruling <n>
#   * apology or self-criticism, and addressing an absent reader
#   * unfinished markers, and a subject over 72 characters
#
# RUN IT BEFORE YOU PUSH, and gate the push on its exit status with `&&`, not
# `;` -- a check whose verdict is not read is not a check:
#
#   bash scripts/dev/check-commit-message-hygiene.sh origin/<base>..HEAD \
#     && git push
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
  # I/O token too, or the acronym reads as the first-person pronoun -- and
  # neutralise short command flags for the same reason: a word boundary falls
  # between the dash and the letter, so a short flag reads as the pronoun.
  # Found by this guard rejecting a message that quoted its own remediation
  # advice. The pattern spells the boundary out as a character class rather
  # than using `\b`, which BSD sed accepts and silently ignores -- so the `\b`
  # form passes on Linux CI and does nothing on a macOS working copy.
  body="$(git log -1 --format='%B' "$sha" |
    sed -E '/^[A-Za-z-]+-[Bb]y:[[:space:]]/d; /^(Signed-off-by|Refs|Fixes|Closes|Reviewed-on):[[:space:]]/d' |
    sed -E 's#I/O#IO#g; s/ -([a-zA-Z])([^[:alnum:]]|$)/ shortflag\1\2/g')"

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
  printf 'State what the code does; put evidence and reasoning in the pull request\n' >&2
  printf 'body instead.\n\n' >&2
  printf 'NOT YET PUSHED: git commit --amend, or git rebase -i for an older commit.\n' >&2
  printf 'ALREADY PUSHED: rewriting a published ref is guarded here, so branch fresh\n' >&2
  printf 'from the last clean commit, replay the change with a compliant message, and\n' >&2
  printf 'open a new pull request. Run this check again over the whole new range.\n' >&2
  exit 1
fi

printf 'Commit message hygiene OK: %d commit(s) in %s.\n' "$(printf '%s\n' "$commits" | wc -l | tr -d ' ')" "$range"
