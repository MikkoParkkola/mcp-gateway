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

The same shape appears on the elicitation path, and there it sits on a blocking row.
`main` constructs an `InputBridge` in production inside `invoke_tool_traced`
(`src/gateway/meta_mcp/invoke.rs`); on integration, `git grep -n InputBridge
origin/codex/v4-next-integration -- src/` returns three hits and all three are inside
`src/gateway/input_bridge.rs` itself. The bridge is defined there and constructed
nowhere. `MIK-7387.STDIO.1`-`.3` therefore cost more on integration than on `main`: the
work is to restore a production call site as well as to implement the channel.

A third loss sits in the gate itself. `main` runs
`cargo clippy --all-targets --all-features -- -D warnings` at `.github/workflows/ci.yml:180`;
the same line on integration reads `cargo clippy --all-features -- -D warnings`. Integration
does not lint test, bench or example targets at all. Two consequences follow. Any lint count
measured against integration's CI is an undercount of what `main`'s CI will demand the moment
the branches meet, so a branch that is green there can go red on merge without a line of
source changing. And `--all-targets` is the command this repository documents as its gate, so
the weaker line is the drift, not the stronger one. Restore it in the same pass that resolves
the merge, and measure the lint backlog against the restored command.

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

## 6. Fourteen of the blocking rows are sequenced behind the merge

The publish gate (`check_scope_acceptance.py --publish-check`) names 28 unresolved
criteria. They do not all represent code that has to be written.

Nine are already satisfied on `codex/v4-next-integration` and graded there row by row
(`LIFECYCLE.1`-`.5`, `STORE.2`, `JOURNEY.2`, `CONTRACT.1`, `SIGNING.1`). Each ledger note
carries the branch citation. They close when integration reaches `main`; no further
implementation is required for them.

Five more are `VALIDATION` rows whose acceptance text names a revision that does not
exist yet:

| Row | What its acceptance requires |
|---|---|
| `NFR.BUILD.1` | coverage and mutation evidence that "grades the final integration revision" |
| `NFR.UPGRADE.1` | an upgrade executed *from* 3.5.1 into the shipping deployment |
| `NFR.WORKLOAD.1` | same-host interleaved measurement against the frozen 3.5.0 baseline and 3.5.1 |
| `NFR.DEMO.1` | recorded demonstrations of five journeys, with versions and actual outcomes |
| `NFR.CONFORMANCE.1` | evidence references for every cell of the role/transport/revision/outcome matrix |

A run recorded against today's `main` would grade the wrong artifact, and
`scope-tests.md:73` rules that out in as many words: "don't grade the branch from an old
protocol-only sample."

Two of the five do have pre-merge work, and it is build work rather than measurement.
`NFR.CONFORMANCE.1` needs the matrix widened — the existing 19-row table on integration
(`tests/mik_7272_conformance.rs:52-292`) has role and transport axes but neither revision
nor outcome, and covers neither modern URL-elicitation completion removal nor
arbitrary-JSON structured results. `NFR.WORKLOAD.1` needs its harness and the frozen
3.5.0 baseline: `benchmarks/` carries no 3.5.0 measurement on either ref, so the
comparison the acceptance text names has nothing to compare against. The version is
specified across the requirement documents and measured nowhere. Building both before the
merge is what makes the post-merge validation pass a measurement rather than a project.

## 7. One row is gated on the deployment, not on the merge

`NFR.SEC.7` is the single blocking row from the baseline ledger
(`RELEASE-4.0.0-criteria-status.md`) rather than from `scope-status.json`, and its
acceptance is a probe against the running process: the build actually listening must
contain every security control merged for the release, compared automatically rather than
by hand. Source inspection cannot satisfy it — it establishes that a guard is wired into
the router, never which revision the listening process was built from. The row therefore
closes after the deployment, behind both the merge and the release, and no amount of
implementation closes it earlier.

That leaves thirteen rows as genuine implementation. Fifteen of the twenty-eight are
sequenced behind the merge and the deploy. Draft state on all fourteen PRs, and the
operator approval behind it, gates more than half the release ledger rather than one
merge commit.

## 8. The dead-code lint is reporting release scope, not debt

`cargo clippy --all-features -- -D warnings` fails on the integration line with a cluster of
zero-caller symbols. Twenty-five of them are one finding rather than twenty-five: a
`personal_accounts` consent and grant subsystem, the response-firewall check
`enforce_firewall_challenge` with the two variants only it constructs, and six singletons of
the same shape.

None of it is disposable. The accounts subsystem is the partial implementation of
`MIK-6744.STORE.1`, `MIK-6745.JOURNEY.1` and `MIK-6745.JOURNEY.3` — three `ACCOUNTS`-tagged
blocking rows that are `not_met` for the reason the lint names, that the subsystem exists and
nothing calls it. Deleting it with its tests would delete work the release has to ship.

`enforce_firewall_challenge` is the sharper case and points back at §7. On integration it has
six test call sites (`src/gateway/meta_mcp/response_challenge_tests.rs:171-251`) against one
definition (`response_security.rs:159`) and no production caller — a merged security control
absent from the behaviour of the build that would listen. That is the condition `NFR.SEC.7`
exists to detect, so suppressing the lint there removes the signal rather than the defect.

Resolution: `#[expect(dead_code, reason = "…")]` per symbol, each reason naming the criterion
that will wire it. `#[expect]` fails the build once the symbol acquires a caller, so the
annotation is removed by the wiring work itself; `#[allow]` would outlive the fix and keep
suppressing. Any symbol that cannot be tied to a row stays failing and gets listed — an
untraceable zero-caller symbol is a question, and answering it by annotation is how it stops
being asked.
