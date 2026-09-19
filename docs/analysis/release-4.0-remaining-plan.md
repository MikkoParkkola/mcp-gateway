# 4.0 release: the remaining plan

Live working plan. Supersedes nothing in the criteria ledger — that file
(`docs/requirements/RELEASE-4.0.0-criteria-status.md`) stays the authority on
what "met" means. This records the *order* the remaining work happens in, why,
and how far along it is.

## Progress metric

Three numbers, reported every tick. Nothing else is progress.

- **Operator steps: 10 / 37 done** (2 of the 37 are operator-gated, see below)
- **Blocking release criteria: 2** — `NFR.SEC.7` and `NFR.PKG.1`, both
  operator-gated. Nothing in the tree closes either one.
- **Rows open but not blocking: 1** — `NFR.PERF.1`, where ruling 69 accepted
  the residual and the blocking cell already reads `no`. Open and blocking are
  different columns; the counter warns about exactly this conflation.
- **Files over the 800-line ceiling: 92**, 67,080 lines of excess (Lane G)

`python3 scripts/release/count-release-criteria.py --check` is the authority on
the second number: 149 criteria, 193 rows, 191 met or non-blocking.
`python3 scripts/dev/check-file-size.py` is the authority on the third.

## What is actually left

Twelve operator asks, decomposed into 37 steps. Grouped by lane, because the
lanes are what can run at the same time.

### Lane A — meta-tool surface compaction, 17 → 11 (the critical path)

Ruled by the operator 2026-09-16: before tagging. "Ship 17, defer to 4.1.0" and
"compact with deprecations" were both offered and declined. Design is committed
(`3c80e533`, 615 lines) and both review seats are answered (`9f601ae1`,
`3f64c7ca`). The cut is implemented: the default HTTP deployment serves 11,
stdio 10, the floor is 9 and the ceiling 17, and every cut name still dispatches.

| # | Step | State |
|---|---|---|
| A1 | Failing tests: surface count, and every cut tool's function reachable at its new home | **done** — `surface_compaction_tests.rs` pins the eleven-name listing and the dispatch of every cut name |
| A2 | Implement the cut in `src/gateway/meta_mcp/` | **done** — six tools gated on the configuration that lets them answer; band 14..=17 becomes 9..=17 |
| A3 | README + every badge + `benchmarks/public_claims.json` + docs, in the same change | **done** — `standing: admin`, `minimum: 9`, `readme_benchmark: 11`, savings 92.67% |
| A4 | Two independent review seats | **done** — both non-Claude seats returned SHIP; two test-strength notes are in flight, no defect |
| A5 | Merge | open — integration branch `lane-a/surface-compaction` carries lanes A, D4, D5, D6 and D7 |

This lane owns `src/gateway/meta_mcp/mod.rs`. Nothing else may touch that file
while it runs.

### Lane B — interim-round defect, both halves (ruling 68)

MRTR.12 (chain stop) is built, green and reviewed (`fb0890ed`). The other two
halves are open.

| # | Step | State |
|---|---|---|
| B1 | MRTR.11a presentation — failing tests | open |
| B2 | MRTR.11a implementation | open |
| B3 | MRTR.11b validation — failing tests, then implementation | open |
| B4 | Review both seats, merge | open |

Runs in its own worktree against `invoke.rs` and the interim modules. Rebases
onto Lane A before merging, never the other way round.

### Lane C — stdio saturation seam (ruling 70)

The deliberate hold stays; the rows close on evidence. Seam at
`src/gateway/meta_mcp/mod.rs:2286` — the same file Lane A rewrites, so the
design and the test are written while Lane A is in flight and the
implementation lands after it merges.

| # | Step | State |
|---|---|---|
| C1 | Design the seam | open |
| C2 | Review the design before any code | open |
| C3 | End-to-end test past the 1024-permit boundary, failing first | open |
| C4 | Implement, after Lane A merges | open |
| C5 | Review, merge | open |

### Lane D — analysis and docs, zero code conflict

Fully parallel with everything. Runs as subagents.

| # | Step | State |
|---|---|---|
| D1 | Multi-user gap list at source: what many-users/one-gateway/per-user-credentials needs that the tree lacks (ruling 72) | open |
| D2 | Size that gap and bring the operator the real number | open |
| D3 | Enumerate the untested conformance cells | **done** — see below |
| D4 | Assert `tools/list` order determinism (`MIK-7272.ORDER.1`) instead of arguing it structurally | **done** — `ac_order_1_one_unchanged_gateway_repeats_the_same_tool_sequence`, ledger row off *(structural)* |
| D5 | Repair the stale `HEADER.5` evidence citation in the conformance matrix | **done** — the row cites the two mirroring tests, renamed to the `ac_` convention the self-check enforces |
| D6 | Relocate the internal process docs out of the public tree | **done** — 107 docs under `docs/internal/`, 123 references repointed |
| D7 | Fix the public-repo hygiene gate | **done** — 27 heading and 5 path markers, 5 fixtures, 0 false positives over 361 tracked docs |
| D8 | Merge the docs change | **done** — merged onto the integration branch, all three hygiene gates green |

**D3 result.** The executable authority is `tests/mik_7272_conformance.rs` — a 21-row
table, green at 8 passed 0 failed — and `RELEASE-4.0.0-conformance-matrix.md` is its
prose reading. Every one of the 21 statements is COVERED; none is marked untested.
The enumeration this step asked for returns an empty list, so D4 and D5 replace it
with what the cross-check against the per-clause ledger actually found:

| Cell | What the label hides | Size |
|---|---|---|
| `MIK-7272.ORDER.1` | MET *(structural)*: determinism comes from straight-line `Vec` construction, and no test calls `tools/list` twice and compares. A switch to a hashed container stays green. (`RELEASE-4.0.0-criteria-status.md:217`) | one unit test |
| `MIK-7214.HEADER.5` | Covered, but by `tests/mik_7214_header5_mirroring.rs`, not by the test the matrix cites | citation repair |
| `MIK-7272.EXT.1`, client half | Cannot discriminate an end-to-end name-list implementation without a request-scoped observation seam, which does not exist | new test seam — out of 4.0.0 scope, recorded as a known limit |

The step was recorded here as "operator decision 19". There is no such row:
`RELEASE-4.0.0-operator-decisions.md` holds 18, and no release document contains the
phrase. The work is still worth doing on its merits, but its provenance is corrected
rather than carried.

### Lane E — the ledger, the notes, the tickets (lead only, never a subagent)

| # | Step | State |
|---|---|---|
| E1 | Apply ruling 69 to the `NFR.PERF.1` row: residual accepted, carrier named, row non-blocking | **done** — verified at source, blocking cell reads `no` |
| E2 | Release-note sentence stating the performance claim is not end-to-end | open |
| E3 | Sync every Linear ticket to this plan, content and status | open |
| E4 | `NFR.PKG.1` — operator-gated, see decisions | open |
| E5 | `NFR.SEC.7` — operator-gated, see decisions | open |

### Lane F — quality sweep and the final gate

Runs last — after Lane G, because a definition-of-done check against a tree
that is still moving is a check of nothing.

| # | Step | State |
|---|---|---|
| F1 | Run the `/!:improve` cycle over the landed 4.0.0 code | open |
| F2 | Land what it finds | open |
| F3 | Resolve the stalled `v4-merge` worktree (7 conflicted files, branch `merge/v4-integration-main`) | open |
| F4 | Home the rescued sole-copy patches, then prune worktrees to zero | open |
| F5 | Final definition-of-done check: section verdicts plus the acceptance-criteria table | open |

## Two decisions that are the operator's, not mine

1. **`NFR.PKG.1`** — the multi-architecture image publish path is written
   (`c8803f06`, #568) and has never executed, because only a version tag fires
   it. It can be proven before 4.0.0 by cutting a release-candidate tag
   (`v4.0.0-rc.1`), which publishes real images to the container registry. That
   is an outward-facing publish, so it waits for a yes.
2. **`NFR.SEC.7`** — the listening install is `3.4.0-f30539af`, which predates
   the origin guard `5d25f104`. The first half of the criterion closes on a
   deployment of a build carrying the guard. Nothing in the tree can close it.

## Invariants that keep this cheap

- **Subagents never edit the criteria ledger.** Every branch touching it
  conflicts with every other. Workers report the rows they affect; the lead
  writes them centrally. Same rule for README and the badges.
- **One file, one lane.** `mod.rs` belongs to Lane A until Lane A merges.
- Branch deletion goes through `bin/safe-delete-branch`, never a bare
  `git branch -D`. Known defect, worked around: that script's forge query
  exceeds GitHub's 500,000-node ceiling; the fix is to drop `commits` from the
  `--json` list and fetch per pull request.
- Before removing any worktree: `git -C <tree> status --porcelain | rg -v target`.
  Non-empty means that tree is the only copy of the work. Six worktrees measured
  zero commits ahead of main and every one held work that existed nowhere else.
- Disk is the recurring hard stop — the root filesystem hit 4.8 GB free during
  this work, and the reclaim is almost entirely `target/` directories inside
  worktrees. Merging and removing worktrees *is* the disk fix.

## Lane G — the 800-line ceiling, before the tag

**Operator ruling 2026-09-19: the large-file refactor happens before the tag.**
It is a definition-of-done criterion, so it is release scope, not post-release
cleanup. This supersedes the earlier "phase 3, after the tag" ordering in
[`post-4.0-simplification-plan.md`](post-4.0-simplification-plan.md), which
stays the authority on *how* each split is done.

Settles the reading dispute: the 4.0 definition-of-done check recorded §2 Code
Quality as `N/A at branch scope`
(`docs/internal/requirements/RELEASE-4.0.0-dod-check.md:356`) on the reading that the
ceiling governs a *change*. It governs a *file*. Under the operator's ruling
the criterion is not met, and Lane G is what meets it.

Measured now by `scripts/dev/check-file-size.py`: **92 files over, 67,080 lines
of excess**. That is the largest single item in the release — larger than the
surface compaction.

| # | Step | State |
|---|---|---|
| G1 | Order the 92 files by excess and by how many open branches touch each | open |
| G2 | Bottom-up mechanical work first (~708 lines; B1 alone is 72% of it and is a half-finished test-fixture migration, not a new abstraction) | open |
| G3 | Retry-loop consolidation — four loops become two | open |
| G4 | The splits themselves, fanned out one file per agent | open |
| G5 | Ceiling reaches zero and the ratcheting baseline file is deleted | open |

Sequencing is forced, not chosen. A split moves thousands of lines between
files and conflicts with every branch touching the same code, so Lane G runs
against a quiet tree: after Lanes A, B and C have merged. The compaction in
Lane A shrinks `meta_mcp` first, which is the right order anyway — splitting a
file and then deleting half its contents is wasted work twice.

Once the tree is quiet, this lane parallelises harder than anything else in the
release: one agent per file, each owning exactly one file, the lead committing
centrally. The gate ratchets, so the number can only go down.

