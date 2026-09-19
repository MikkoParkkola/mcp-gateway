# 4.0 release: the remaining plan

Live working plan. Supersedes nothing in the criteria ledger — that file
(`docs/requirements/RELEASE-4.0.0-criteria-status.md`) stays the authority on
what "met" means. This records the *order* the remaining work happens in, why,
and how far along it is.

## Progress metric

Three numbers, reported every tick. Nothing else is progress.

- **Operator steps: 16 / 37 done** (2 of the 37 are operator-gated, see below)
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
| A5 | Merge | **open, operator-gated** — [#599](https://github.com/MikkoParkkola/mcp-gateway/pull/599) carries lanes A, D4, D5, D6 and D7: 22 commits, 191 files. Merge to `main` waits for a yes |

This lane owns `src/gateway/meta_mcp/mod.rs`. Nothing else may touch that file
while it runs.

### Lane B — interim-round defect, both halves (ruling 68)

**This lane is closed.** All three halves are built and on the release line.
MRTR.12 (chain stop) is `fb0890ed`; MRTR.11a and MRTR.11b both landed in
`fafc943a`, merged through #561. The ledger credited them to `935d31d8`, a
commit that reached no release-line branch — the code arrived by a different
route and the citation has been repaired to the commit that actually carries
it.

| # | Step | State |
|---|---|---|
| B1 | MRTR.11a presentation — failing tests | **done** — `interim_promotion_tests.rs` |
| B2 | MRTR.11a implementation | **done** — `promote_interim`, `src/gateway/meta_mcp/interim_promotion.rs:54` |
| B3 | MRTR.11b validation — failing tests, then implementation | **done** — an unvalidated claim is answered `-32603`, never wrapped |
| B4 | Review both seats, merge | **done** — merged through #561 |

Runs in its own worktree against `invoke.rs` and the interim modules. Rebases
onto Lane A before merging, never the other way round.

### Lane C — stdio saturation seam (ruling 70)

The seam citation in the earlier draft of this plan named
`src/gateway/meta_mcp/mod.rs:2286`, which is the wrong file — that line holds
an unrelated backend-name helper. The gate is in the stdio serve loop:

- `src/gateway/server/mod.rs:76` — `STDOUT_QUEUE_DEPTH = 1024`
- `src/gateway/server/mod.rs:89` — `MAX_INFLIGHT_STDIO_REQUESTS`, tied to it
- `src/gateway/server/mod.rs:99` — `admit_stdio_request`, deliberately not
  `async`, so the read loop cannot park on admission
- `src/gateway/server/mod.rs:108` — `stdio_busy_response`, `-32000`, and
  `None` for a notification
- `src/gateway/server/mod.rs:2563` — the admission call site, `try_send` and
  `continue` on refusal

All of that is already on `main`. The design it implements is
`docs/design/2026-09-13-mik-7387-stdio-concurrent-dispatch.md`, whose §5 and §6
the doc comments cite by number, and the non-blocking admission gate is its
addendum of 2026-09-16 (line 250). That design was reviewed **before** any code
existed — two independent reviews, both SHIP-WITH-FIXES, with the revision
folded in and each finding named at the section it changed (line 8); the
addendum carries its own two reviews (line 252) and a third review pass is
recorded at line 456. A merge would not have established this; the design
document does. So the design and implementation rows close on that evidence and
the lane reduces to the proof nobody wrote.

| # | Step | State |
|---|---|---|
| C1 | Design the seam | **done** — recorded in the doc comments cited above |
| C2 | Review the design before any code | **done** — two independent pre-implementation reviews, design doc line 8; addendum reviewed at line 252 |
| C3 | End-to-end test past the 1024-permit boundary | **done** — `tests/mik_7212_mrtr7_stdio_acs.rs:978` and `:1131` |
| C4 | Implement | **done** — on `main`, cited above |
| C5 | Review, merge | **done** — merged through #561 |

**Lane C is closed.** The coverage was already there and an earlier draft of
this plan missed it. `ac_mrtr_7a_the_reader_keeps_reading_past_the_admission_cap`
(`:978`) and `ac_mrtr_7b_the_excess_past_the_inflight_cap_is_refused_not_queued`
(`:1131`) drive the real binary past the cap, and both were mutation-checked
before they landed: halving `MAX_INFLIGHT_STDIO_REQUESTS` reddens 7b, and
restoring the inline `acquire_owned().await` in the read loop reddens both.
That is the red/green proof, recorded at the time rather than reconstructed.

The unit test at `src/gateway/server/mod.rs:5025` is the narrow companion to
those two, not the whole of the coverage — reading it alone is what made this
lane look open.

### Lane D — analysis and docs, zero code conflict

Fully parallel with everything. Runs as subagents.

| # | Step | State |
|---|---|---|
| D1 | Multi-user gap list at source: what many-users/one-gateway/per-user-credentials needs that the tree lacks (ruling 72) | in flight — landing in `docs/internal/analysis/multi-user-gap.md` |
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

### Lane H — unverifiable evidence citations (found 2026-09-20)

The ledger cites 99 commit SHAs as proof that criteria are met. **35 of them are
reachable from no release-line branch.** The first one examined, `935d31d8` on
two rows, turned out to be a pre-squash SHA: the code did land, under
`fafc943a` through #561, and only the citation was dead. That repair is done.
Whether the other 35 are the same benign case or a criterion marked MET against
code that never shipped is the open question, and the second case would be a
release blocker.

| # | Step | State |
|---|---|---|
| H1 | Classify all 35: remapped, present-by-content, or genuinely missing | **done** — `docs/internal/analysis/ledger-sha-remap.md`: 34 remapped, 0 present-by-content, 1 missing |
| H2 | Rewrite the citations the classification repairs (lead only) | **done** — 56 citations repointed across 34 commits; a re-sweep reports `checked=63 unreachable=1`, the one being the missing commit itself |
| H3 | Re-grade any criterion whose evidence turns out to be absent | **done** — `MIK-7272.SUB.2b` regraded MET (caveat) → PARTIAL and blocking; see Lane I |
| H4 | Gate it: fail CI when the ledger cites a commit unreachable from the release line | open |

The one that did not remap was `9cf1557b`, two acceptance tests and nothing
under `src/`. Recovered from the object database with
`git show 9cf1557b -- tests/ | git apply`, restored on
`fix/sub2b-command-backend-progress` at `edb1c0d9`, and one of the two then
failed three runs of three — against a defect that had been live the whole
time. The distribution is what made it dangerous: 34 clean remaps build
exactly the confidence that waves the 35th through.

### Lane I — the command-backend progress leg (opened 2026-09-20 by Lane H)

`MIK-7272.SUB.2b` is blocking. A `command:` backend's progress notification
cannot reach the client before its call settles, by construction: the
notification is pushed onto a `Vec` at `src/transport/stdio.rs:482` and that
`Vec` is published only from `ProgressRegistrationGuard::drop`
(`src/transport/stdio.rs:622-627`). This is the collect-then-emit shape
ADR-014 §1 rejects. The accumulation is load-bearing rather than an oversight —
`notification_sink::publish` resolves its destination from a task-local the
reader task does not have in scope, so publishing at capture time would drop
silently (pinned by `publish_outside_a_scope_is_dropped_not_panicked`,
`src/transport/notification_sink.rs:302`).

| # | Step | State |
|---|---|---|
| I1 | Design the repair: carry the caller's sender with the registered token | **done** — `docs/design/2026-09-20-sub2b-command-backend-progress.md`, ratified before code |
| I2 | Two independent reviews of the design | **done** — gpt SHIP, grok SHIP-WITH-FIXES; grok's HIGH finding (the map must store the caller's token as well as the sender, or `translate_back` cannot restore it on the live path) verified at source and folded in |
| I3 | Failing test on the release line | **done** — `edb1c0d9`, red as designed |
| I4 | Implement against the ratified design | open |
| I5 | Re-grade the row once green | open |

## Housekeeping — build trees

`merge/v4-integration-main` holds a half-finished merge that is **redundant**:
the commit it is merging, `992b87c3`, is already an ancestor of `origin/main`,
and the checkout sits 339 commits behind main, so the 45,695 deletions in its
diff are simply the commits it lacks. It carries no commit of its own. Its
resolution is archived at
`.archive/v4-integration-main-stale-merge-2026-09-20.patch` (36,138 lines).
Clearing it needs a hard reset of a dirty checkout, which is an operator
action, not an agent one.

`lane-a/surface-compaction-test-strength` was removed on 2026-09-20: its 23
commits were already contained in the pushed `lane-a/surface-compaction`, so
the branch carried nothing of its own (archived at `refs/archive/by-tip/6e3de6d9`).

### Lane E — the ledger, the notes, the tickets (lead only, never a subagent)

| # | Step | State |
|---|---|---|
| E1 | Apply ruling 69 to the `NFR.PERF.1` row: residual accepted, carrier named, row non-blocking | **done** — verified at source, blocking cell reads `no` |
| E2 | Release-note sentence stating the performance claim is not end-to-end | **done** — a note under the `[4.0.0]` heading in `CHANGELOG.md`: component benchmark, no P50 or P99, worst shared case +6.07% |
| E3 | Sync every Linear ticket to this plan, content and status | **done** — `MIK-7265`, `MIK-7481`, `MIK-7272` and `MIK-7212` carry the current state; `MIK-7212` moved back to In Progress |
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
| F4 | Home the rescued sole-copy patches, then prune worktrees to zero | part done — 3 worktrees retired, 14 GB reclaimed (43 GB free). `695e66bd` was a sole copy, pushed to `origin/rescue/meta-mcp-surface-republish` and then found fully superseded. 7 remain: `v4-merge`, 2 locked, 2 unmerged-and-dirty, 1 test-strength, 1 root |
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
| G1 | Order the 92 files by excess and by how many open branches touch each | in flight — landing in `docs/internal/analysis/file-size-ceiling-order.md` |
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

