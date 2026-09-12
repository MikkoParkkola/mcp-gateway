# v4.0.0 merge path — measured 2026-09-12

Refs measured: `origin/main` at `738c7cee`, `origin/codex/v4-next-integration` at `dbc06304`,
merge-base `c3626cf8`. Every number below comes from `git merge-tree --write-tree` and
`git diff --numstat`; nothing was checked out and no branch was modified.

## 1. Why #512 conflicts

`origin/main` is **11 commits ahead of the merge-base**, not one. Those commits carry the
single-license flip (ADR-013), the backend protocol-version negotiation fix (GH #517), the
multi-round tool-result work, and the Windows `APPDATA`/`LOCALAPPDATA` stdio fix.

`git merge-tree --write-tree origin/main origin/codex/v4-next-integration` reports
**109 conflicted files: 73 add/add and 36 content**.

The add/add majority is not parallel reimplementation. It is squash-merge ancestry loss —
integration's work reached `main` as squashed commits, so git sees no common blob for those
paths and reports every one of them as "both sides added this file". The tell is the diff
size:

| Path | main | integration | diff |
|---|---|---|---|
| `src/protocol/task_store.rs` | 148 | 148 | +1 / −1 |
| `src/gateway/input_bridge.rs` | 606 | 593 | +2 / −15 |
| `src/protocol/mrtr.rs` | 461 | 491 | +31 / −1 |
| `src/protocol/tasks.rs` | 136 | 437 | +378 / −77 |

Bucketing all 73 add/add files by total changed lines between the two sides:
18 differ by 5 lines or fewer, 31 by 6-50, 18 by 51-200, and 6 by more than 200. So a third
of the add/add set is structural noise and two thirds carry real divergence; the label alone
does not tell you which. The genuine work is the 36 content conflicts plus the 24 add/add
files above 50 lines.

## 2. Neither branch is a superset

Integration is 779 commits ahead, but it does **not** contain everything on `main`:
`LOCALAPPDATA` appears in `main`'s `src/` and in zero files on integration, so the Windows
stdio fix (#522) is absent there. A one-directional "take integration" resolution would
silently drop it.

## 3. The stacked PRs are small; their diffs are not

Every PR targeting `codex/v4-next-integration` carries 1-4 commits. The five-figure diffs
GitHub shows are an artifact of a stale base: each branch is 85-267 commits *behind* the
branch it targets, and the compare view charges that drift to the PR.

Measured against current integration with `git merge-tree --write-tree`:

| PR | own commits | behind base | conflicting files |
|---|---|---|---|
| 502, 503, 506, 508, 509, 511 | 1-2 | 85-218 | 0 |
| 510 | 1 | 85 | 1 (`src/personal_accounts/mod.rs`) |
| 501 | 2 | 219 | 7 |
| 499 | 4 | 267 | 7 |

Six of the nine independent PRs merge clean today. Four more sit behind `#501`:
`#501` is an ancestor of `#504` and of `#507`, and `#507` is an ancestor of `#513`.
Resolving `#501`'s seven files is therefore the single highest-leverage act in the queue —
it unblocks four PRs, not one.

## 4. Recommended order

1. Merge `origin/main` **into** `codex/v4-next-integration` and resolve there — one pass, on
   the branch that is ahead, with the 12 stacked PRs still based on their own parent.
   Resolving on the `main` side instead would re-resolve the same 109 files once per stacked
   PR.
2. Land the stacked PRs into integration. Seven are already `MERGEABLE`
   (#511, #509, #508, #506, #503, #502) and seven conflict against their own base
   (#513, #510, #507, #504, #501, #499) — those conflict with integration, independently of
   the `main` question, and each needs its own rebase.
3. Only then re-open #512 (integration → main). After step 1 it is a fast-forward-shaped
   merge rather than a 109-file resolution.

## 5. Merge readiness

**All fourteen open PRs are drafts.** None can merge today regardless of conflict state,
and operator approval is required before any of them does. Draft state is the binding
blocker; `CONFLICTING` is the secondary one.

| PR | base | state |
|---|---|---|
| 528 | main | draft, MERGEABLE |
| 512 | main | draft, CONFLICTING |
| 513, 510, 507, 504, 501, 499 | integration | draft, CONFLICTING |
| 511, 509, 508, 506, 503, 502 | integration | draft, MERGEABLE |
