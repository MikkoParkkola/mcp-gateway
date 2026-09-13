# 4.0.0 release-readiness — resume point

Written at a session boundary so the next session can start cold. Plan and
rationale: `RELEASE-4.0.0-CLOSE-PLAN.md`. Shard contract: `PR473-REVIEW-BRIEF.md`.

> **Stale — do not resume from the table below.** It records branch
> `fix/mrtr2-continuation-handle` at `7bdd733c`, which is not the release line. The release
> line is `feat/sub2b-outbound-mint` (PR #528), and the counter there reads
> `149 criteria, 189 rows, 188 met or non-blocking, 1 blocking`, not 21. Every command in
> the right-hand column still works and is still the way to re-check; only the recorded
> answers have moved.
>
> Current entry points:
> [`RELEASE-4.0.0-gap-assessment-2026-09-11.md`](../../requirements/RELEASE-4.0.0-gap-assessment-2026-09-11.md)
> for readiness and the two ledgers, and
> [`RELEASE-4.0.0-blocking-rollup.md`](../../requirements/RELEASE-4.0.0-blocking-rollup.md)
> for which recorded rows have since gone stale.

## Where things stand

| fact | how to re-check |
|---|---|
| branch `fix/mrtr2-continuation-handle`, head `7bdd733c` | `git log --oneline -1` |
| criteria counter is CLEAN — no malformed rows, no drift warnings | `python3 scripts/release/count-release-criteria.py` |
| 146 criteria, 183 rows, 21 blocking | same command, last line |
| the 21 blocking ids enumerate mechanically | `python3 scripts/release/count-release-criteria.py --blocking` |
| counter tests green, 38 of 38 | `python3 scripts/release/test_count_release_criteria.py` |
| one red lib test | `honest_task_tokens::tests::schema_only_100_tools_matches_readme_model` |
| CodeQL FAILURE on PR #473 | the only red check on the PR |
| 326 of 329 changed files still unreviewed | shard reports in this directory, most verdicts PENDING |

## Next actions, in order

1. **The red lib test is OURS, not inherited.** Triaged 2026-09-08: the range
   `c3626cf8..HEAD` changes both the constant and the assertion —
   `README_META_TOOLS` 16 -> 17 (`src/honest_task_tokens.rs:20`) and
   `benchmarks/public_claims.json` `readme_benchmark` 16 -> 17, with the test
   updated to 1_700 tokens and 88.667%. The assertion is therefore intentional
   and the failure is a real disagreement between the model and the constants.
   Run `cargo test --lib honest_task_tokens` and read which assert fires — that
   run was still in flight when the session ended, so the deciding line is not
   yet known. Heavy Mac builds go through `lowload`.
2. **CodeQL triage** — `codeql-triage.md`, `codeql-dispose.md` in this directory.
3. **Collect shard verdicts.** Every report here with `PENDING` under Findings is
   unfinished. A verdict is a ledger row with `process_status: ok`, never text
   scraped from output. Re-dispatch the shards whose reports are still PENDING.
4. **Assess the 21 blocking criteria** from the mechanical list. Each needs a
   met/not-met verdict with evidence and a test that can fail.
5. **Release paperwork** — DoD section verdicts and an AC pass/fail table posted
   as an issue comment, functional pass, dual-vendor final review, then the
   delivery chain steps 1-5.

## What the reboot destroys

Every running subagent dies: `fixer-metamcp`, `fixer-security`, `fixer-protocol`,
`pr473-plumbing`, `pr473-gateway`, `protocol-grok-row`, `pr473-tests-a-2`,
`pr473-tests-breadth`. Their committed work survives; anything they held only in
context does not. Re-dispatch from the shard contract, not from memory.

## Uncommitted files are NOT this session's

`git status` shows around twenty modified files under `docs/design/`,
`docs/requirements/`, `src/` and `tests/`. They belong to concurrent sessions
working the same worktree. Do not commit them, do not revert them, do not clean
them. The git index is SHARED — always `git commit -o <paths>`, never `git add .`.
