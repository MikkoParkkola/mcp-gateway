# PR #473 unreviewed-slice review — shared brief

Operator decision 2026-09-08: review ALL 326 unreviewed files of PR #473 before
merge. 3 files (2,902 ins) were already reviewed at 5cb4f4e9; everything else in
the range has been read by nobody.

## Pinned revision

    BASE=c3626cf8      # merge-base; local main is 7 behind origin, use this literal
    HEAD=60b138bb10a869703254eae2fe500f055d96f8d7

## Build your payload from the PINNED SHA, never the worktree

A worktree diff picks up concurrent sessions' uncommitted files and peers'
commits. Both have happened here and both wasted a full review round.

    git diff c3626cf8 60b138bb -- <your paths> > payload.diff

Record `sha256sum payload.diff`. That hash, not the ledger `head` field, is what
binds a verdict to what was actually read.

## Run two vendors on IDENTICAL material, via stdin

    ~/.claude/bin/gpt-review  < payload.diff
    ~/.claude/bin/grok-review < payload.diff     # kimi-review if grok errors

- Material goes on STDIN. A path argument makes the reviewer review the filename.
- Run them in your task's FOREGROUND. `nohup` inside a background task dies with it.
- Reasoning takes minutes: Bash timeout >= 300000ms.
- A verdict is the LEDGER ROW (`~/.claude/data/{gpt,grok,kimi}-review-ledger.jsonl`),
  never text scraped from the output. `process_status` must be `ok`; a nonzero
  exit is ERROR, not a verdict.
- An empty run file may be a race. MISSING only after the process exits.
- If a payload exceeds ~150KB, split it and review each half; say so in your report.

## Every finding is a LEAD until you check it at source

Today's rate: roughly 1 in 4 reviewer findings dies on inspection. For each:

    CONFIRMED     — cite file:line proving it
    DEAD          — cite file:line disproving it
    CANNOT-VERIFY — say precisely what you could not determine

Do NOT relay a finding you have not checked. Do NOT fix anything: this is a
review pass, findings go in the report and the operator decides.

## Report

Write `docs/release/verify/<your-shard-name>.md`:

- payload sha256 + byte count + file count + insertion count
- both ledger rows (ts, verdict, material_sha256, process_status)
- every finding with its CONFIRMED/DEAD/CANNOT-VERIFY verdict and deciding file:line
- severity for confirmed findings, and whether it blocks a 4.0.0 release
- anything you could not cover, stated plainly — silent truncation reads as coverage

Commit on the SHARED index, path-scoped, or you will commit a peer's work:

    git add docs/release/verify/<name>.md
    git commit -o docs/release/verify/<name>.md -m "docs(verify): <subject>"

Commit style: `type(scope): summary` <=72 chars imperative, blank line, then
bullets only. No first person, no session narration — write it as if a stranger
reads the public repo.

## Correction — reviewer launch and ledger binding (2026-09-08, supersedes the text above)

Two instructions above were wrong. Both were found by the `pr473-gateway` shard.

**1. Foreground is impossible; use a harness-tracked background task.** The brief asks
for the run in the task foreground AND a Bash timeout of at least 300000ms. Those
contradict: the Bash tool caps a foreground call at 120s. The constraint the rule was
reaching for targets `nohup`/`&`/`disown`, which detach and die with the parent turn.
A harness-tracked background task does NOT die that way. Launch reviewers as a tracked
background task, and take each verdict from the ledger row rather than from the task's
own exit reporting.

**2. `material_sha256` is NOT the payload hash.** `gpt-review`'s `digest_material`
hashes `printf '%s\0' "$*"` followed by the stdin file. For a stdin review with no
scope arguments the digest therefore covers one NUL byte plus the payload, and
`material_bytes` is always payload bytes **+1**. Matching a ledger row to a payload by
comparing `sha256sum payload.diff` against `material_sha256` will never match and
reads as a missing verdict. To bind a row to a payload, recompute the digest the same
way:

    { printf '\0'; cat payload.diff; } | sha256sum

and expect `material_bytes` to equal payload bytes + 1. The `head` field remains
non-binding — the wrapper stamps it from repo HEAD at launch, not from what was read.
