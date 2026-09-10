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
Both causes of the red `Tests` run are addressed at source, but **R1 is not closed and
must not be read as closed.** What was measured is narrower than what CI runs, in two
ways worth stating so nobody mistakes the local numbers for the verdict:

- The two runs are `cargo test --test mik_7212_mrtr_component_acs` (19/0 at `a43ea83d`)
  and `cargo test --test mik_7215_acs` (26/0 at `3f50cf62`). Neither saw the other's
  commit, and neither ran at `db828e0e`. The `unfinished_round` guard is now upstream of
  the mrtr bridge fix and no run has exercised the two together.
- CI runs `cargo test --all-features --no-fail-fast`. Both local runs used the default
  feature set, so `spec-preview` and `runtime-substrate` are unexercised.

Step 3 — the `Tests` job on `db828e0e` — is what decides R1, and it is already running.
`CodeQL` is untouched; read its alerts from this run, not from the run on `482746c1`,
because the branch has moved four commits and one of them edits `router/handlers.rs`.
