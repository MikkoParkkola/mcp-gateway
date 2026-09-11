# 4.0.0 release-readiness — gap-closure plan (draft for adversarial review)

## Goal

PR #473 merged and 4.0.0 shippable with the FULL scope: every blocking release
criterion met with evidence, no red checks, no unreviewed code.

## Where the release actually stands

| fact | evidence |
|---|---|
| branch compiles; 4054 lib tests pass | `cargo test --lib` on the branch |
| the red lib test is GREEN as of 2026-09-08 | `cargo test --lib honest_task_tokens` = 6 passed, 0 failed. `README_META_TOOLS` moved 16 -> 17 with matching assertions; base `c3626cf8` still carries 16/1_600/89.333 |
| NEW red: `cargo clippy --all-targets -- -D warnings` fails | 3 errors, all in `tests/common/mod.rs`, a file this PR adds (absent from `c3626cf8`) — so the failure is the PR's, not inherited |
| CodeQL FAILURE on #473 | the only red check on the PR |
| 21 blocking criteria of 183 rows | `rg -c '\| yes \|' docs/requirements/RELEASE-4.0.0-criteria-status.md` = 21; `\| no \|` = 162 |
| 326 of 329 changed files never reviewed by anyone | PR473-REVIEW-BRIEF.md, operator decision 2026-09-08 |
| shard reports written, verdicts mostly PENDING | `docs/release/verify/pr473-*.md` |

## Buckets

- **B1 — blocking criteria.** 21 rows. Each needs met/not-met with evidence, and a
  test that can fail. Not yet determined: how many are already met, because
  `count-release-criteria.py --blocking` is malformed on `MIK-7272.EXT.1` and cannot
  enumerate them mechanically.
- **B2 — red signals.** CodeQL failure plus a clippy failure in `tests/common/mod.rs`.
  The lib-test red named above has since gone green on its own; the clippy red replaced it
  and is the one that now blocks, because CI gates on `-D warnings`.
- **B3 — unreviewed code.** ~27K insertions across the shards; verdicts still PENDING
  in most shard reports. Expected to add findings; how many is not yet established.
  Covers the whole changed surface INCLUDING the 21.6K-line test diff, at two depths:
  a deep can-this-test-fail audit of the AC tests backing the 21 blocking rows, and a
  proportionate pass over the remaining tests. Depth varies with risk; coverage does
  not, because a release that claims no unreviewed code cannot carve out a third of
  the diff.
- **B4 — release paperwork.** DoD §1-§13 verdicts, AC pass/fail table posted to the
  issue, dual-vendor final review, functional pass, delivery-chain steps 1-5.

## Critical path

```
  repair the criteria counter (gates reconciliation) -+
  triage CodeQL + the red test (B2)                  -+
  finish shard reviews, land verdicts (B3)           -+- parallel
  assess and repair blocking criteria (B1)           -+
  functional pass as soon as a surface runs (B4)     -+
                    |
                    v
  fold B3 findings into the blocking set
                    |
                    v
  fold B3 findings into the blocking set
                    |
                    v
  CLOSE each blocking criterion (test that can fail + evidence)
                    |
                    v
  refresh B4 evidence against the final candidate, dual-vendor review, merge
```

## Sequencing rationale

1. **The counter gates final RECONCILIATION, not every criterion.** Rows that are
   already identifiable by id can be worked now; what the broken enumeration prevents
   is the closing claim that all 21 are accounted for, and hand transcription has
   already produced two disagreeing counts in this repo (37 vs 31). Diagnosed
   2026-09-08: the blocking cells are fine. `rows()` anchors its id regex with `$`
   (`scripts/release/count-release-criteria.py:31`), so the ledger's clause-qualified
   form `MIK-7272.EXT.1 (clause: declare)` fails the match, falls to the
   `ID_PREFIX` branch (`:158-160`), and is reported under a message naming the wrong
   column. Two rows, one regex.
2. **B2 is cheap and gates the merge absolutely.** A red check blocks the merge
   regardless of criteria state. The failing test is one assertion about a documented
   token model; either the model or the assertion is wrong, and deciding which is a
   read, not a project.
3. **B3 gates criterion CLOSURE, not criterion WORK.** A reviewer finding that lands
   after a criterion is closed reopens it, so closure waits. Assessment and repair do
   not: they run concurrently with B3, and only the criteria a later finding actually
   touches get reworked. The earlier draft put a global barrier here and paid for it
   across all 21 rows to protect the few that a finding would reach.
4. **B4 is assembled incrementally, not at the end.** The functional pass runs as soon
   as there is something runnable, because an integration failure found at the last
   stage costs a whole cycle. Evidence collected early is refreshed against the final
   candidate rather than gathered from scratch.

## What is deliberately NOT on the critical path

- Paperwork audits of the criteria ledger's non-blocking 162 rows. They do not gate
  ship. The `shard-5` agent doing that audit has been stopped.

(An earlier draft excluded most of the test diff from review. That contradicted the
release's own no-unreviewed-code requirement and has been withdrawn — see B3.)

## Open questions this plan does not answer

- How many of the 21 blocking criteria are already met? Not established until the
  counter is fixed. The plan's shape does not depend on the answer; its size does.
- Will B3 add blocking findings? Not established. Historical rate in this repo:
  roughly 1 in 4 reviewer findings dies at source, so a raw finding count overstates
  the work.
- Is the CodeQL failure a real defect or a scanner artifact? Untriaged.

## Review question

Is this the fastest correct order, or does it serialise something that could run
concurrently? Attack the sequencing, not the prose.

---

# Re-measured 2026-09-10 — what is left, and in what order

Everything in this section was measured this session; the command that produced each
number is inline. The section above is the 2026-09-08 record and is left intact — its
counts (21 blocking, a clippy red in `tests/common/mod.rs`, an untriaged CodeQL run) have
all been overtaken.

## The shape has changed: the gate is no longer the constraint

| fact | evidence |
|---|---|
| criteria gate passes | `python3 scripts/release/count-release-criteria.py --check` exits 0: "146 criteria, 183 rows, 181 met or non-blocking, 2 blocking" |
| 2 blocking rows, both owned | `--blocking` prints exactly `MIK-7272.SUB.2b` and `MIK-7272.SUB.4` |
| the release PR is #473 into `main` | `gh pr list --base main` — the only non-dependabot PR targeting `main` |
| 16 further PRs are stacked behind it | every other open PR has `baseRefName: fix/mrtr2-continuation-handle` |
| #473 is MERGEABLE but BLOCKED | `gh pr view 473 --json mergeable,mergeStateStatus` |
| two red checks on #473 | `Tests` (run `34488524723`) and `CodeQL` (check run `102909138871`) |

So the release is gated on four things, not on the criteria ledger: two red checks, one
approving human review, and the two remaining blocking rows.

## R1 — `Tests` is red for two independent reasons, one already fixed

Run `34488524723` on head `482746c1` fails `cargo test --all-features --no-fail-fast`
in two targets:

**R1a — `mik_7212_mrtr_component_acs`, 3 passed / 16 failed. FIXED, unpushed.**
`14744d72` on `fix/mrtr2-continuation-handle` adds one condition to the Legacy-era bridge
guard in `src/gateway/meta_mcp/invoke.rs` so that an interim carrying no questions is not
treated as an exchange to bridge. Verified independently, not taken from the commit
message: a detached worktree at `14744d72` with a scratch `CARGO_TARGET_DIR` runs
`cargo test --test mik_7212_mrtr_component_acs` to **19 passed / 0 failed, exit 0**.

**Correction, 18:20 — that commit was not one push away, and the number above was
measured on the wrong base.** `fix/mrtr2-continuation-handle` as checked out in
`/Users/mikko/github/.worktrees/mcp-2026-protocol` is **70 commits behind origin** and one
ahead: `git rev-list --left-right --count origin/fix/mrtr2-continuation-handle...fix/mrtr2-continuation-handle`
returns `70	1`, and `git merge-base --is-ancestor origin/fix/mrtr2-continuation-handle 14744d72`
is false. Pushing that branch tip is a non-fast-forward that would drop 70 commits of
origin. **Do not push that worktree's branch.** The 19/0 above was measured at `14744d72`,
i.e. on the 70-behind base, so it said nothing about whether the fix holds at origin tip.

Resolved by cherry-pick, not by push. `src/gateway/meta_mcp/invoke.rs` has zero origin
commits since the merge-base `6f745477`, and so does `tests/mik_7212_mrtr_component_acs.rs`,
so the pick was textually clean. Re-measured on the new base — `a43ea83d`, the cherry-pick
on top of origin tip — the same command returns **19 passed / 0 failed, exit 0** again.
That is the number that counts. Pushed as `77f564f8..a43ea83d`.

**R1b — `mik_7215_acs`, 24 passed / 2 failed. LANDED as `3f50cf62`, 26/0.**
`http::ac_confirm_1_a_modern_destructive_call_with_nobody_to_ask_is_refused` and
`http::ac_confirm_1a_a_refusal_is_excluded_from_both_accounting_arms` assert
`/error/code == -32001`. The gateway returns `resultType: "input_required"` carrying
`inputRequests["io.mcp-gateway.destructive-confirmation.v1"]`. Reproduced at `14744d72`
on a clean tree, so it is not another lane's dirty state.

This is not a regression. It is the contradiction `confirm2-blocker.md` predicted in
advance: CONFIRM.2's in-band ask and CONFIRM.1a's HTTP refusal assert opposite outcomes
for the same request, and CONFIRM.2 landing made the ask the real one. The `CONFIRM.1a`
ledger row already carries the resolution — the refusal is conditional, it binds where
confirmation genuinely cannot be obtained, and it stays witnessed by
`ac_confirm_1a_stdio_refuses_a_destructive_call_it_cannot_confirm`
(`src/gateway/server/mod.rs:2835`) and `tests/mik_7246_confirm_1a_unconfirmable_producers.rs`.
What has not landed is the corresponding edit to the two HTTP tests.

That edit exists, uncommitted, in `tests/mik_7215_acs.rs` (+87/-41): it renames the first
test to `..._is_asked_in_band_and_not_run` and retargets both to the in-band outcome,
asserting the extension key rather than the method alone. It needs
`rustfmt --edition 2024` (three diffs, lines 755/765/1028) before commit. `cargo fmt` on
single files drops the edition and invents errors.

**Consequence worth stating: a `PASS` row's own acceptance tests are red.** The verdict
survives on the stdio witnesses, but until the retarget lands the ledger and the test
suite disagree in public.

## R2 — `CodeQL` is red on five alerts the existing triage does not cover

`gh api repos/.../check-runs/102909138871/annotations` (the `code-scanning/alerts`
endpoint returns 404 for this token):

| level | location | rule |
|---|---|---|
| failure | `src/config/mod.rs:275` | Hard-coded cryptographic value |
| failure | `src/config/mod.rs:283` | Hard-coded cryptographic value |
| failure | `src/gateway/meta_mcp/support.rs:407` | Weak cryptographic hashing on sensitive data |
| failure | `src/gateway/webhooks/tests.rs:471` | Hard-coded cryptographic value |
| failure | `src/gateway/webhooks/tests.rs:508` | Hard-coded cryptographic value |

`pr473-codeql.md` triages check run `101939020717` — a different rule family
(path-injection, cleartext-transmission) — so the actionable set here is untriaged.
The first step is the `most_recent_instance.ref` separation that pass already
established: the check's own caveat is that a large diff pulls in alerts belonging to
`main`, and last time that accounted for three of five. Two of these five are in a
`tests/` target that ships in no release artifact. The three library hits are the ones
that matter, and a genuine hard-coded key or weak hash on a sensitive value in `src/`
is stop-the-line, not triage-and-move-on.

## R3 — the two blocking criteria

**`MIK-7272.SUB.2b`, ABSENT.** The outbound leg has now been written (a per-request
notification sink, the stdio production registration the inbound leg never had, and a
request-scoped event stream). The library compiles; the new tests are unverified because
the disk guard tripped mid-lane. The guard has since cleared — 11.0 GB free by
`statvfs('/')`, against a 5 GB threshold — so the remaining work is running the gate, not
writing code. The standing merge constraint holds: the inbound scaffold lands with the
outbound leg or not at all.

**`MIK-7272.SUB.4`, PARTIAL.** Three known holes, all verified at source, all of which
duplicate a side effect:
- the backend-error exit at `backend_handlers.rs:862-867` never settles the reservation,
  so `impl Drop for IdempotencyReservation` (`src/idempotency.rs:562-571`) takes the
  `Release` arm and hands the caller's retry a clean key. `settle_direct_idempotency`
  completes only when `response.error.is_none()`, so a JSON-RPC error releases it too.
  A transport failure after the side effect landed is indistinguishable from one before.
  The fix is a terminal `Failed` state instead of release-on-error.
- `src/backend/ops.rs:218` wraps the caller's `tools/call` in `with_retry`, so the
  backend's own transport retry re-sends beneath the guard with no client retry involved.
- `identity_suffix` (`src/gateway/meta_mcp/invoke.rs:1128-1132`) is empty when identity
  propagation is off, which is the shipped default, so two authenticated callers derive
  one key.

## R4 — the delivery chain, which no amount of green fixes

`reviewDecision` is empty on #473. Its three bot reviews are all `COMMENTED`, never
`APPROVED`. Nothing in the 16-PR stack can reach `main` until #473 merges, and #473
cannot merge without an approving human review. This is an operator action and no lane
can substitute for it.

## Order of work

1. ~~Push `14744d72`.~~ **Done, by cherry-pick.** That branch was 70 commits behind
   origin and could not be pushed; see the correction under R1a. The fix is on origin as
   `a43ea83d`, re-verified 19/0 on the new base. `.worktrees/mcp-2026-protocol` still has
   the stale branch checked out at `14744d72` — its commit is redundant now, and its
   branch must not be pushed.
2. ~~`rustfmt --edition 2024 tests/mik_7215_acs.rs`, commit the retarget, push.~~
   **Done as `3f50cf62`.** The owning lane went unreachable with the pair uncommitted, so
   merge-integration landed it: rustfmt with the edition flag, `git commit -o` on the two
   paths, rebase onto `FETCH_HEAD`, re-measure. `cargo test --test mik_7215_acs` returns
   **26 passed / 0 failed, exit 0** on the rebased base, up from 24/2.
3. Re-run `Tests` on #473 and confirm green rather than assuming it.
4. Triage the five CodeQL alerts: split branch from `main`, read the three library hits
   at source, fix what is real, propose dismissal for what is not. Dismissal is the
   operator's call.
5. Run the SUB.2b gate now the disk has recovered; land inbound and outbound together.
6. Close SUB.4's three holes, `Failed` state first — it is the one that duplicates a
   mutation on the exact path the criterion names.
7. Empty the expected-red register. It has one entry
   (`mik_7215_control4_reap_count_acs`, owner control4-lifecycle, PR #516 open) and its
   own rule is that it must be empty at RC.
8. Operator review and merge of #473, then unstack the 16.

Steps 4, 5 and 6 are independent and can run concurrently. Steps 3, 7, 8 are strictly
ordered after them.

**Branch state as of 18:22.** `origin/fix/mrtr2-continuation-handle` is `3f50cf62`, four
commits past the `482746c1` that CI last measured: two release docs (`811ed56d`,
`77f564f8`), the mrtr bridge fix (`a43ea83d`), and the CONFIRM.1a retarget (`3f50cf62`).
**R1 is closed.** The `Tests` job — `cargo test --all-features --no-fail-fast`, the same
job that was red — succeeded on `db828e0e` in CI run `34501035875` (job window
16:16:37Z–16:18:17Z, 2026-09-10), and the whole `CI` workflow is green on that commit and
on the current tip `c0486097`. The local runs recorded below are narrower than that job in
two ways, which is why the CI verdict is the one that counts: What was measured is narrower than what CI runs, in two
ways worth stating so nobody mistakes the local numbers for the verdict:

- The two runs are `cargo test --test mik_7212_mrtr_component_acs` (19/0 at `a43ea83d`)
  and `cargo test --test mik_7215_acs` (26/0 at `3f50cf62`). Neither saw the other's
  commit, and neither ran at `db828e0e`. The `unfinished_round` guard is now upstream of
  the mrtr bridge fix and no run has exercised the two together.
- CI runs `cargo test --all-features --no-fail-fast`. Both local runs used the default
  feature set, so `spec-preview` and `runtime-substrate` are unexercised.

Step 3 is therefore done. What remains before merge is `Analyze (rust)`, still running, and
the CodeQL alerts; read its alerts from this run, not from the run on `482746c1`,
because the branch has moved four commits and one of them edits `router/handlers.rs`.

---

# Post-#473 gap assessment and closure plan — 2026-09-11

The goal at the head of this document ("PR #473 merged and 4.0.0 shippable") is
half satisfied: **#473 merged 2026-09-10T16:37 as squash `0f04a179`** onto
`c3626cf8`, and `feat/mcp-2026-protocol` is deleted. This section is the state
after that merge and the sequence from here to shippable at full scope.

## State, measured

| fact | evidence |
|---|---|
| `origin/main` = `ed796575` | `fix(protocol): negotiate and adopt the backend's protocol version (GH #517) (#520)` |
| main is green | `gh run list --branch main`: CI, Docker, Push on main all `success` at `ed796575`, 2026-09-10 21:52 |
| the green run is the DoD's "full suite" | `.github/workflows/ci.yml:198` runs `cargo test --all-features --no-fail-fast`, which is DoD item 8's definition |
| the 14 failures recorded on 2026-09-03 are closed | they were in three branch-new binaries (`mik_7212_acs`, `mik_7212_mrtr_component_acs`, `mik_7272_conformance`) that merged inside #473; the merged state passes the same command |
| **5** criteria still block | `scripts/release/count-release-criteria.py --check` → 149 criteria, 189 rows, 184 met or non-blocking, 5 blocking |

## Gap A — the five blocking criteria

| id | requirement | owner | where it stands |
|---|---|---|---|
| `MIK-7272.SUB.2b` | request-scoped notifications MUST flow on the response stream of their own request | peer session (`sse-decoder`) | inbound leg built; **ABSENT on the outbound leg** |
| `MIK-7217.OUTBOUND.1` | no method in `REMOVED_IN_2026_07_28` reaches an `Era::Modern` backend, on any of the four outbound call sites | this session | fail-first suite red (11 of 32 in `src/backend/tests.rs` + `src/transport/http/tests.rs`); design reviewed twice, both SHIP-WITH-FIXES; **zero production code changed** |
| `MIK-7217.OUTBOUND.2` | only a result resets the breaker, only a fault trips it, an unserved answer escalates | this session | same increment; `health_probe` still matches on the transport result alone (`src/backend/lifecycle.rs:1053`) |
| `NFR.SEC.7` | the listening build carries every merged security control, and merged-versus-listening drift is detected automatically | **unowned** | governs MIK-7265, which is Blocked because its own deliverable — the drift-check script — is unbuilt |
| `GH475.RL.5` | the `throttl` stem does not exempt | **unowned** | re-read at source 2026-09-11: holds for `throttling`, because the predicate has no `throttling` arm |

Five, not six, and the sixth candidate is the one worth naming. `NFR.PERF.1` is
PARTIAL and is *not* on this list, while `GH475.RL.5` is PARTIAL and is. The
grade is not the discriminator. The blocking flag is the row's **last** cell,
which `rows()` requires to read exactly `yes` or `no`
(`scripts/release/count-release-criteria.py:152`); read directly,
`GH475.RL.5`'s reads `yes` and `NFR.PERF.1`'s reads `no`. That flag was
cleared by the operator's 2026-09-05 ruling, quoted in full on its
`RELEASE-4.0.0-criteria-status.md` row and summarised at
`RELEASE-4.0.0-blocking-rollup.md:217` — *it did not get met, it got ruled
non-blocking*. So the re-measurement in step 5 is hygiene against a stale
figure, not a sixth blocker, and the release-note number stays 5.

## Gap B — obligations no criterion row reaches

The ledger states the limit in its own words: the rows are *a sample of each
ticket's obligations, not a cover, and the sampling is uneven*. Four consequences
are load-bearing for this release:

- **`MIK-7217` AC.2 (`MCP728.DISCOVER.2`)** requires `server/discover` on five
  *other* repositories. No ledger row reaches it. This is the largest unscoped
  item in the release and the only one that leaves this repository.
- **`MIK-7256`** carries 26 ACs and is graded through a single row (`NFR.SEC.6`,
  on mechanism). The triage reads the ACs directly: 0 FAIL / 9 PASS / 6 PARTIAL
  / 11 NO TEST — **17 ACs with no verifying test**.
- **`MIK-7320`** and **`MIK-7265`** had no requirement row at all until
  2026-09-11; they are now governed by DoD item 8 and `NFR.SEC.7` respectively,
  each by one gate.
- **Name collision.** `MIK-7217.DISCOVER` is 11/11 MET in the ledger;
  `MCP728.DISCOVER.1-8` is a different list at 1/8 in the triage. Reading the
  first as "the discovery ticket is done" is wrong by seven criteria.

## Gap B2 — the five release tickets no gap above reaches

The triage lists twelve tickets In Progress. Gaps A and B reach six of them
(`MIK-7272`, `MIK-7217`, `MIK-7265`, `MIK-7256`, `MIK-7320`, `GH475`). The
remaining five — **`MIK-7212`, `MIK-7213`, `MIK-7214`, `MIK-7215`,
`MIK-7116`** — have no open engineering work: their code merged inside #473 and
is on `main` at `ed796575`. What is outstanding for them is bookkeeping, and the
triage is explicit about why that is not a formality: a bucket-A ticket *moves
to Done when the branch merges, not before*, and an issue closed against an
unmerged branch is a false green. The merge exists now, so the state move is
owed, with `0f04a179` as its evidence. This is the same work the D13b/c/d
bookkeeping gates in Gap C call for, and it is the only thing standing between
these five and Done.

## Gap C — DoD gates that apply and were never run

`RELEASE-4.0.0-dod-check.md` measured the full gate set at `c3083368` — a
different branch, dated 2026-09-03, before the #473 squash — and found that
**21 applicable gates were never run**. That set has not been re-enumerated at
`ed796575`. The gates are unrun either way, but *which* gates apply may have
moved with the 85 `src/` files the merge brought to `main`, so treat the
buckets below as the last enumeration rather than as today's posture — invisible rather than open until
that table existed. They fall in three buckets:

| bucket | gates | runnable now? |
|---|---|---|
| analysis nobody has done on this branch | H7 (redundant docs), H9 / D4 (duplication), D5 (contract diff), D7 `pub` half, D28 (API surface), D29 (debt trajectory) | yes |
| needs a deployed system | §9 ops, D8 / D22 (observability emission), D20 rollback, D21 canary, D23 alerting, D26 sec-monitor, B3 durable resume | no — operator's call |
| bookkeeping | D13b effort, D13c deps, D13d labels, D17 learnings | yes |
| unanswered on purpose | T1c post-quantum readiness — flagged rather than guessed, because a wrong N/A is the hole the gate exists to close | yes, one decision |

Two numeric gates carry **stale figures, not passes**:

- **Coverage** was measured at `edfd020a` and found **below the floor**. It was
  not re-measured at `c3083368` and has not been measured since #473 merged.
  This is an open blocker wearing an old date.
- **Mutation ≥75% on new code** passed at `edfd020a` on `src/protocol` only. No
  figure exists for the rest of the changed surface.
- **`NFR.PERF.1`** is PARTIAL: latency measured on `spark` 2026-09-03, `v3.5.0`
  (`32f135a6`) against a head that predates the merge. Needs a re-run at the
  release head.

One gate is blocked outside the code: the dual-vendor review gate, because the
second vendor returns `402 Payment Required`.

## Gap D — merge and forge debt, and its single cause

16 open PRs, every one based on `main`; **14 of them CONFLICTING**.

The squash is the cause. Each `codex/v4-*` branch and
`fix/mik-7215-control4-reaper` forks from release history that `main` now
carries as one commit, so each reports 1699–1963 commits "ahead" and conflicts
wholesale. Measured against the squashed release tree (`0f04a179`) rather than
against `main`, the real deltas separate cleanly:

| PR | branch | real `src/` delta vs `0f04a179` | disposition |
|---|---|---|---|
| #522 | `fix/windows-stdio-appdata` | none in `src/` | MERGEABLE — cheapest merge on the board |
| #521 | `fix/gh517-protocol-negotiation` | 19 files, +1517/−166 | GH #517 landed as #520; re-cut the remaining idempotency half on `main` |
| #516 | `fix/mik-7215-control4-reaper` | 83 files, +539/**−4376** | **behind, not ahead**; its criterion `MIK-7215.CONTROL.4` already reads MET ("wired end to end") on `main` |
| #499–#513 (13 drafts) | `codex/v4-*` | 35K–64K insertions each, stacked on one another | v4 accounts / OpenWebUI / task signing — **none maps to a blocking row or a 4.0.0 ticket** |

Behind the PRs: **82 remote branches unmerged into `origin/main`** and **46
worktrees**. The fan-out is itself the readiness problem. Everything below
converges — merge, close, or park — and opens no new branch that is not required
by a blocking row.

## Gap E — the ledger's own summary contradicts its table

`RELEASE-4.0.0-criteria-status.md` still carries prose (~line 520, dated
2026-09-06) reading *"thirteen of the 22 are blocking … nine ABSENT … three
PARTIAL (`NFR.PERF.1`, plus `NFR.OBS.1` and `NFR.OBS.2`)"*. The live table and
`count-release-criteria.py` both say **5 blocking**, and `NFR.OBS.1` is MET with
its stdio half landed at `d306c7e8` and its falsifier probe recorded. A reader
who quotes the prose over-reports the release gap by eight criteria. The prose
is stale; the table and the script are the authority. Fixing it is a
release-readiness item in its own right, because the release note will quote a
number.

## The plan

Ordered by dependency, not by size. One item in flight at a time; an item is
done when its gate is *run*, not when its code is written.

**1 — Finish the in-flight increment (`MIK-7217.OUTBOUND.1` + `.2`).**
Two independent reviews landed SHIP-WITH-FIXES and converge on the same open
ruling. Fold all five fixes in *before* any production code is written, because
the suite is the fail-first evidence and editing it after the mechanism lands
forfeits that:

- close §3 by teaching `is_session_expired_error` an `Error::JsonRpc` arm that
  matches `-32015` or a "session not found" message **only** — do not lift
  `-32600` onto the `Err` arm, and keep parsing 404 bodies (404 is the
  `STATELESS.5b` refusal carriage, so exempting it would make the status-carried
  arm unreachable on the real HTTP path);
- add the referee row rows 16 and 16d cannot adjudicate: a 404 carrying `-32601`
  with an echoing id is `Error::JsonRpc` and is not retried;
- record rows 6b, 8b and 9c as second-stage pins beside 6/9b/9d, and correct
  §7's count — coverage is overstated by five re-observations, not three;
- give row 9b the follow-tick assertion its own cell writes;
- fix row 16's comment: `error.rs:159` is `TransportConnect`, not `JsonRpc`.

Then implement against the red suite. **Closes 2 of the 5.**

**2 — `GH475.RL.5`.** Add the `throttling` arm to the rate-limit exemption
predicate, plus a test that a `throttling`-stemmed method is not exempt.
Smallest blocking row on the board and currently unowned. **Closes 1 of 5.**

**3 — `NFR.SEC.7` / `MIK-7265`.** Build the merged-versus-listening drift check:
enumerate the security controls merged to `main`, compare against what the
listening build actually exposes, fail CI on divergence. This *is* MIK-7265's
own deliverable and the reason the ticket is Blocked, so it closes a criterion
and unblocks a ticket in one move. **Closes 1 of 5.**

**4 — `MIK-7272.SUB.2b`.** Owned by the `sse-decoder` session. Track it; do not
duplicate the work. If that session is confirmed dead — no commit and no
worktree mtime movement — adopt the row rather than leaving it unowned.
**Closes the 5th.**

**5 — Re-measure the two stale numbers at the release head.** Coverage (below
floor at `edfd020a`) and `NFR.PERF.1` (spark, 2026-09-03, against `32f135a6`).
Both belong on `spark`. Coverage below the floor is a real blocker whose staleness
is the only reason it is not on the blocking list.

**6 — `MIK-7256`'s 17 untested ACs.** Write them. Sized M in the triage.

**7 — `MIK-7217` AC.2, cross-repo `server/discover` on five repositories.**
Scope it explicitly — land it, or record a named, dated deferral. Leaving it
unscoped is the failure mode, not leaving it undone.

**8 — Forge convergence.** Merge #522. Re-cut #521's idempotency half on `main`.
Closing #516 is outward-facing and awkward to undo, so the supersession was
checked at source before it was written down rather than inferred from the
−4376: the branch's own six reaper commits (`4dd45d29`, `5ca38eaa`, `faa9b035`,
`b1fa1585`, `7ef0f598` and `1e203cf0`) are all reflected on `main`, and
`git diff origin/main origin/fix/mik-7215-control4-reaper -- src/gateway/session_lifecycle.rs src/gateway/streaming.rs`
is empty. `main` carries `pub fn reap(&self, now: u64) -> usize` at
`src/gateway/session_lifecycle.rs:152`, the reclaimed-count return the branch
was opened to add. The residual +539 is release and CI documentation churn on
the pre-squash base. Close #516 citing the `MIK-7215.CONTROL.4` ledger row as the reason it is
superseded. Relabel the 13 `codex/v4-*` drafts post-4.0.0 and take them off the
release board. Then prune worktrees whose branches are merged or parked —
checking for local-only commits first, per the delete gate.

**9 — Run or reason-away the 21 unrun DoD gates.** The six analysis gates (H7,
H9, D4, D5, D28, D29) and the four bookkeeping gates are runnable now. T1c needs
one decision: does this release introduce a new key-agreement or signature
primitive? The nine that need a deployed system are the operator's call and get
a recorded N/A with its reason, never a silent skip.

**10 — Repair the ledger prose (Gap E)** and take the release-note number from
`count-release-criteria.py --check`, not from any hand-written figure.

## Assumptions, stated rather than asked

The standing instruction is to proceed without operator questions, so these are
decisions taken, not questions parked:

- **`MIK-7256`**: full scope means the 17 untested ACs get tests, not an accepted
  residual. The triage defers this to the operator; full scope answers it.
- **The `codex/v4-*` fleet is post-4.0.0.** Nothing in 13 drafts totalling
  ~60K insertions maps to a blocking row or to any of the 12 release tickets.
  Treating them as release scope would triple the release and close nothing.
- **#516 closes as superseded**, on the strength of its own criterion reading MET
  on `main` and its branch being 4376 deletions behind the merged tree.
- **`MIK-7243` stays deferred** — it is the one item the backlog triage records
  as deferred from 4.0.0. `MIK-7116` is *not* deferred; it sits in bucket A and
  moves to Done when its branch merges.

## Progress, 2026-09-11

**Item 1 — `MIK-7217.OUTBOUND.1` + `.2`: done.** Committed as `0a009d6f`, twelve
files. `cargo test --lib row_` is 43 passed / 0 failed against the landed
mechanism, from 22 passed / 16 failed at the branch point; `cargo fmt --check` is
clean. Row 10b failed against the landed mechanism rather than against the branch
point and found a real defect in it: the escalation tripped the breaker and
rebuilt the transport without clearing the count it had just acted on, so the
tolerance was spent once and never again. The implementation review pair was kimi
and grok, `gpt-review` being credit-exhausted until 2026-09-15; kimi returned
ship, with one behavioural narrowing repaired in the same commit — both error
carriages now read the same session-expiry marker set, so a peer that words its
expiry no longer loses session recovery by the accident of having sent a body
that parses.

**Item 2 — `GH475.RL.5`: closed by ruling, and this plan's step 2 was wrong.**
Step 2 above says to add a `throttling` arm to the predicate. The predicate needs
no such arm: it has never matched `throttling`, and the case the published test
plan named is already asserted. The half that failed was the past participle, and
building step 2 as written would have made "request throttled by upstream" count
as a circuit-breaker failure — the behaviour #475 was opened to remove.

The clause moved instead of the predicate, because the clause has no source in
the issue it is named after: #475 never uses the word, and both the clause and its
test case were authored in our own test plan, alongside a case narrower than the
clause itself. The amended clause still forbids a `throttling` phrase and the two
literal negations from exempting, the boundary of those two negations is now
asserted rather than left to a doc comment, and the capacity-failure residual is
recorded in the ledger cell rather than hidden by the grade. The ruling was
reviewed adversarially before it was written down and narrowed in response: the
first draft claimed "unless negated", which would have certified a
natural-language negation the predicate does not implement.

`count-release-criteria.py --check` now reports 149 criteria, 189 rows, 185 met
or non-blocking, **4 blocking**. Cluster J is cleared in the rollup.

**Item 3 — `NFR.SEC.7` / `MIK-7265`: design written, not yet reviewed.**
`docs/design/2026-09-11-merged-versus-listening-drift-check.md`. It rules for a
behavioural probe as the verdict with build provenance as corroboration, rather
than the ancestry comparison the criterion's wording invites, because a control
can be merged into a build and still disabled, shadowed or unwired — an ancestry
check would be green while the listening build serves exactly the request the
criterion says it must refuse.
