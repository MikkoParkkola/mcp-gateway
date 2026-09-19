# 4.0 release: the remaining plan

Live working plan. Supersedes nothing in the criteria ledger — that file
(`docs/requirements/RELEASE-4.0.0-criteria-status.md`) stays the authority on
what "met" means. This records the *order* the remaining work happens in and
why.

## Where the release stands

`python3 scripts/release/count-release-criteria.py --check`:

```
Coverage: 149 criteria, 190 rows, 188 met or non-blocking, 2 blocking.
Core open: 3 rows neither MET nor N/A (NFR.SEC.7, NFR.PERF.1, NFR.PKG.1).
```

## Phase 1 — clear the release blockers

| # | Item | State |
|---|---|---|
| 1 | **NFR.SEC.7** — merged-vs-listening drift. Second half done (`scripts/dev/check-control-drift.py`, verified against a release build: `2 probed, 1 uncovered, 0 failing`). First half — "the listening build carries every merged security control" — still open. | Blocking |
| 2 | **NFR.PERF.1** | Open |
| 3 | **NFR.PKG.1** | Open |
| 4 | **PR #561** — the only conflicting PR. Its conflict resolution is in-flight in the `v4-stage-tracker` worktree (unresolved merge markers in `ci.yml`, `CHANGELOG.md`, `invoke.rs`, and three ledger docs). | Conflicting |
| 5 | **PRs #585, #586, #587** — mergeable, CI running. | Queued |

Rule that keeps this cheap: **subagents never edit the criteria ledger.** Every
branch that touches it conflicts with every other. Workers report the rows they
affect; the lead writes them centrally.

## Phase 2 — merge everything, then empty the branch list

Land every open PR, then drive local branches and worktrees to zero. Branch
deletion goes through `bin/safe-delete-branch` — never a bare `git branch -D`.

Known gate defect, worked around but not fixed: that script's forge query
exceeds GitHub's 500,000-node ceiling and refuses branches for a reason that
carries no evidence about the branch. Upstream fix is to drop `commits` from
the `--json` list and fetch per PR.

Before removing any worktree: `git -C <tree> status --porcelain | rg -v target`.
Non-empty means the tree is the only copy of that work — six worktrees measured
zero commits ahead of main and every one held work that existed nowhere else.
Commit and push first, then remove.

## Phase 3 — simplification, only once phase 2 is empty

Full plan: [`post-4.0-simplification-plan.md`](post-4.0-simplification-plan.md).

The order is forced by merge cost, not by value:

1. **Bottom-up first** (~708 lines, mechanical). B1 alone is 72% of it and is a
   half-finished test-fixture migration, not a new abstraction.
2. **Retry-loop consolidation** (T1) — four loops become two.
3. **File splits last** (T2a/b/c). A split moves thousands of lines between
   files and conflicts with every branch touching the same code. It runs
   against a quiet tree or not at all.

The target the splits serve is the **800-line-per-file ceiling**, a
definition-of-done criterion. Measured today: **91 files over, 64,284 lines of
excess** (76 in `src/`, 15 in `tests/`). `scripts/dev/check-file-size.py` gates
it in CI and ratchets off a baseline, so the number can only go down.

Note the reinterpretation: the 4.0 DoD check recorded §2 Code Quality as
`N/A at branch scope` on the reading that the ceiling governs a *change*
(`docs/requirements/RELEASE-4.0.0-dod-check.md:356`). It governs a file. Under
that reading the criterion is not met, and phase 3 is what meets it.

## Housekeeping, continuous

Disk is the recurring hard stop — the root filesystem hit 4.8 GB free during
this work. Reclaim is almost entirely `target/` directories inside worktrees,
so merging and removing worktrees *is* the disk fix. Removing two finished
trees returned 15 GB.
