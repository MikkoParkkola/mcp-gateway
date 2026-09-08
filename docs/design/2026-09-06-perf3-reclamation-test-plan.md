# Test plan — NFR.PERF.3 reclamation

Status: historical observer-only plan, superseded for idle reclamation by
`2026-09-06-continuation-scheduled-expiry.md` EXPIRY.1–8. The old row 2's
`len(now)` invokes cleanup and MUST NOT be used as an idle-expiry oracle.
Retain its review history below as historical evidence only. Change A's observer
regressions remain useful; Change C's raw snapshot and real serving lifecycle
are required to close MRTR.8b / NFR.PERF.3.
Design: `docs/design/2026-09-01-nfr-perf3-reclamation.md`, including its 2026-09-06 receipt update
and the same-day correction that hands the lifetime mechanism to MRTR.8b.
Depends on: `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md` Design A
(`InFlight::guard(now)`). Row 2 cannot compile, let alone pass, before it lands — see its
can-fail cell, which is the point of it.

`NFR.PERF.4` is not covered here and never was this slice's: the ceiling, its assertion and its
open breaking-change question all live in `docs/design/2026-09-02-perf4-meta-tool-ceiling.md`,
which owns the production change that turns the assertion green. A second plan writing the same
case would have been the duplicate the review caught.

## Scope of this plan

One row per clause of `NFR.PERF.3` as the clause is worded in
`docs/requirements/RELEASE-4.0.0-requirements.md:283`. No row asserts anything about the capacity
constant itself, about `NFR.PERF.1`, or about the meta-tool surface.

| # | criterion clause | the case that proves it | level | type | can it fail today, and on what |
|---|---|---|---|---|---|
| 1 | memory MUST NOT grow unboundedly with abandoned continuations — the bound holds | **no new case: `ac_mrtr_8_the_table_is_bounded`, `tests/mik_7212_acs.rs:491`, already is it** — fill to the injected capacity with live, unexpired holds, then `hold` once more and get `None` | unit, existing | boundary | **No — already met, and already covered.** `hold`'s capacity branch is built (`:696-717`) and a committed case asserts the refusal. This row's whole content is the citation plus the falsifier probe below, which is what turns an existing green test into evidence for *this* clause |
| 2 | …and a soak with abandonment MUST show reclamation | abandon exactly the table's capacity of exchanges against a **driven clock** and never attempt one more, so the capacity branch is never entered; advance `now` past the deadline; `len(now)` is 0 | unit, own target | lifetime / state | **Yes — but not today, and not on the assertion.** `InFlight::len` is `len(&self)` today (`continuation.rs:756`): no clock. `len(now)` therefore does not *compile* until Design A lands, and a compile error is not evidence about reclamation. The assertion-level red is earned by a falsifier probe run *after* `guard(now)` lands: delete the reclaim call from `guard`, and the row goes red on the occupancy assertion — every entry retained past its deadline, because reclamation otherwise runs only inside the capacity branch and this fixture never enters it. Restore, re-run, and the pass is what proves the restore |

## Why no wall-clock soak

The requirement names no duration, no abandonment rate and no reclamation threshold — recorded as
an unknown and resolved in the design's receipt update. A wall-clock soak would therefore be
inventing its own bound, would not run in the suite, and would be a weaker observation than the
driven clock: it can only show that reclamation happened *somewhere* in the interval, where row 2
shows it happened *at the deadline*. The clock is already a parameter on `hold` (`now: u64`, `:696`) and Design A extends it to
the readers — `len` acquires it there, which is why row 2 is written against Design A's signature and not
today's. Either way: no sleeping and no timing tolerance.

## Assertion strength — the second question a plan review must answer

Every row states above what makes it fail. The risks specific to this plan:

- **Row 1 writes no test at all, because one exists.** Specifying a second fill-to-capacity case
  would have been a second copy of a bound that already has one (`tests/mik_7212_acs.rs:491`), and
  two cases asserting one property drift. What row 1 owes the clause is therefore the citation and
  the falsifier probe — the existing case is green, written after the mechanism, so it inherits none
  of the free failure and is not yet evidence for anything. The probe is a **mutation, not a revert.** An earlier draft
  named "restore the pre-`ec11dcec` body of the capacity branch", and that probe cannot go red:
  `ec11dcec` added the reclaim call and deleted `reap`, but the `held.len() >= self.capacity ->
  None` refusal predates it, and this row's fixture holds nothing expired, so the reclaim is a
  no-op against it and the restored body refuses identically. A probe that passes both ways is a
  ceremony. Delete the refusal itself instead — the two lines that return `None` — and
  `ac_mrtr_8_the_table_is_bounded` goes red on its own assertion (`Some` returned at capacity),
  which is the assertion the clause needs. Restore, re-run, and the pass is what proves the restore, never `git status`.
- **Row 2 must not reclaim through the path that already works.** Two ways it could: calling
  `complete` on the abandoned exchanges, or reaching capacity before asserting. The second is the
  subtle one — `hold` reclaims on a refused attempt, so a fill that overshoots the ceiling drains
  the table through the existing branch and the row goes green with `guard(now)` never involved.
  Hence exactly the capacity and not one more. An earlier draft filled 8 192 "so the table wraps
  its own ceiling once", which is also just wrong: attempts past the ceiling are refused, occupancy
  never exceeds it, and nothing wraps. So the constraint is made **self-enforcing rather than
  commented**: every `hold` in the fill asserts `Some`, and `len` at the fill clock asserts the
  capacity before the clock moves. A later capacity-semantics change, or one stray extra hold, then fails
  loudly on those instead of quietly draining the table through the branch that already works and
  turning the row green for the wrong reason.
- **Row 2 pins the deadline edge, not just the far side of it.** `len` is asserted equal to the
  capacity at `now == deadline` before advancing past it. The retain predicate keeps entries whose deadline is
  at or after `now` (`continuation.rs:675-677`), so without this assertion an over-eager reclaimer
  that dropped not-yet-expired entries would produce exactly the same final 0 and pass. It is also
  what makes good on this plan's claim that the driven clock shows reclamation *at the deadline*
  rather than somewhere in an interval.
- **The admission-recovery row was deleted, not repaired.** An earlier draft carried a third row —
  after row 2's drain, a fresh `hold` at the advanced clock returns `Some` — presented as failing
  evidence of the wedge. It is not: `hold`'s capacity branch already calls `reclaim_abandoned(now)`
  and re-checks (`continuation.rs:696-717`), so against 4 096 expired holds that case returns
  `Some` **today**, through the path that already works. It would have been a green row wearing a
  red label. Its stated justification — that a reclaimer could empty the map while leaving capacity
  accounting stale — describes a state this module cannot reach, because `held.len()` *is* the
  accounting. One map, one number, no second bookkeeping to drift.

## Two corrections the test code forced, neither a design event

Recorded here rather than in the design section because neither meets a §P3 trigger: no acceptance
criterion moves, no contract changes, nothing enters or leaves what §P0 declared FOR or OUT. They
are §P4a documentation updates, recorded now because the case has been written against them, and
are not going back through §P4 on their own account.

- **Row 2's case belongs in its own target, `tests/nfr_perf3_reclamation.rs`, not "the same module".**
  Cargo builds one binary per file in `tests/`, and this row is deliberately red-because-unbuilt.
  Put beside the MIK-7212 criteria it would take that whole binary down — including
  `ac_mrtr_8_the_table_is_bounded`, which is *row 1's entire evidence*. Breaking a committed green
  test for one clause in order to land an intentional red for another is not a trade this plan
  makes, least of all on a branch eleven worktrees share.
- **The capacity is injected as 4, not read from `IN_FLIGHT_CAPACITY`.** The constant is private to
  the crate (`continuation.rs:811`) and widening it would be a visibility change asking for design
  authority this row does not need. Hardcoding `4_096` beside it would duplicate a private
  production value that drifts on the next tune. The property row 2 actually asserts is *fill
  exactly to capacity, never one more*, which is identical at 4 and at 4 096 — so the fixture binds
  the number once and loops over it, and `InFlight::new("gw-1", 4)` is the same shape
  `tests/mik_7212_acs.rs:496` and MRTR.8b row .08 already use. The production number keeps its own
  assertion in MRTR.8b .08, in the module that can see it.

## What is deliberately not covered

- Memory or RSS. Bounded at 4 096 entries either way, so any RSS assertion passes against the
  unfixed code — recorded in the design as the wrong assertion rather than omitted silently.
- The at-capacity O(4 096) walk under the lock. It is a real finding, raised against MRTR.8b's
  design where the code lives; a performance assertion here would test a mechanism this slice does
  not own.
- Anything about the meta-tool surface. `docs/design/2026-09-02-perf4-meta-tool-ceiling.md` owns
  `NFR.PERF.4`, including the deletion of the seventeenth tool, the matching
  `benchmarks/public_claims.json` edit, and the operator question gating both.

## Review record

Verdicts below are read from the review ledger rows, never from a run file's trailing text.
A row counts only with `process_status: ok` and a `material_bytes` matching the payload actually
sent.

| round | payload | vendor | verdict | ledger row | run |
|---|---|---|---|---|---|
| 1 | 11246 B | kimi | `SHIP-WITH-FIXES` | `2026-09-06T07:05:54Z`, `ok` | `synthetic-20260906T070343Z-88057` |
| 1 | 11246 B | grok | `SHIP-WITH-FIXES` | `2026-09-06T07:10:47Z`, `ok` | `grok-20260906T070343Z-88052` |
| 2 | 10054 B | kimi | `SHIP-WITH-FIXES` | `2026-09-06T07:26:38Z`, `ok` | `synthetic-20260906T072110Z-3246` |
| 2 | 10054 B | grok | `SHIP-WITH-FIXES` | `2026-09-06T07:34:15Z`, `ok` | `grok-20260906T072820Z-71115` |

**Two ledger rows in this window are transport failures wearing verdicts, and are excluded.**
Both satisfy the positive `verdict_bearing` test — a row exists, `process_status` is `ok`, the
verdict is in the set — while having read nothing, which is exactly why they are named rather
than left for a later reader to match on `material_bytes` alone:

- `grok`, `2026-09-06T07:18:11Z`, `material_bytes: 11246`, run `grok-20260906T071013Z-16076`. The
  run died at the preamble; its output is 382 bytes of narration with no finding in it. It also
  carried the round-1 payload, so its bytes collide with the genuine round-1 grok row above.
- `kimi`, run `synthetic-20260906T071840Z-85930`, `DO-NOT-SHIP`. The reviewer was handed a
  filesystem path and has no filesystem, so it reviewed the path string; its single finding says
  so. `synthetic-review` must receive material on **stdin**.

### What each round changed

Round 1 produced four findings across the two vendors and **every one was answered by deletion**:
the admission-recovery row, both `NFR.PERF.4` rows, and the 8 192-entry fill. In particular the
`NFR.PERF.4` finding was closed by removing the criterion from this plan altogether, *not* by the
earlier ratchet-plus-`#[ignore]` split that the design's own repair note describes — that split
was the design-round answer to a different finding, and carrying it into the test plan would have
left two documents specifying one assertion.

Round 2 is the confirmation pass, returned to the vendor that raised each finding. Both vendors
independently landed on the same defect — row 2 claimed an assertion-level red that was in fact a
compile error, because `InFlight::len` takes no clock today — which is the strongest evidence in
this record that it was real. grok reviewed the payload as it stood before the kimi repairs, so
its first finding and two of its three improvements were already closed by the time its verdict
was written; its fourth, that row 1 duplicated a committed test, was the only new one and is the
last repair commit.

### Residual

Neither row's falsifier probe has been run, and neither can be: both are specified against
`InFlight::guard(now)`, which lands with MRTR.8b. The probes are the only thing making either row
evidence rather than a green test, so **this plan is not discharged until they run** — owner: this
slice, trigger: the first commit after MRTR.8b lands. If a probe fails to go red, the row it
belongs to is not a case and the clause it claims to cover is uncovered.

Row 2's case is **written and deliberately out of tree** until `guard(now)` lands. MRTR.8b has no
code committed at all — design and plan documents only — so the dependency is unstarted rather than
merely unmerged, and this plan's own landing order puts this slice after it. A file that fails the
build and lint gates on a branch eleven worktrees share would buy a compile error this plan already
says is not evidence about reclamation, at the price of everyone else's gate. The case therefore
waits in this session's scratchpad as `nfr_perf3_reclamation.rs`, reproducible from row 2 and the
two corrections above if the session ends first.

It briefly was in tree: another session's broad commit swept the staged file into `ea61525c` and
the corrections above into `e174b8bd`, and the file was removed again in the commit carrying this
paragraph. Recorded because a reader tracing the file's history will otherwise read that add as a
decision this plan made.

Three things fall at one trigger — the first commit after MRTR.8b lands. Both falsifier probes, and
moving the case back into `tests/` with a check that its compile failure is `len`'s arity **and
nothing else**. That last check is unrun today: the disk guard (MIK-4777) halts the toolchain below
5 GB free and the recovery freeze forbids clearing it. A red caused by a stray typo or a wrong
import looks identical to the red this row wants, which is why it is named as owed rather than
assumed.

No vendor has reviewed the plan as it now stands. grok's round-2 verdict predates `98f25160`, the
repair made in response to grok's own improvement, and repair-protocol step 6 would return that
commit to grok. Closed without a re-check because the repair is the finder's prescription applied
verbatim — row 1 points at `ac_mrtr_8_the_table_is_bounded` instead of specifying a second
fill-to-capacity case, which is the improvement's text — leaving no interpretation to the author.
Recorded rather than assumed, so that closing by silence does not become the habit.
