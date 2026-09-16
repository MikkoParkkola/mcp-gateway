<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Re-grading the 4.0.0 Linear tickets against their own acceptance criteria

The burndown tracked in `v4.0.0-burndown-tracker.md` counts requirement-document
rows. The operator's scope authority is Linear, and the ledger says in its own
words that requirement rows are "a **sample** of each ticket's obligations, not a
cover". `RELEASE-4.0.0-near-done-triage.md` is the file that grades tickets
against their literal ACs, and it was last updated 2026-09-12. This is its
re-derivation against source at `a768d218`, done read-only and ticket by ticket.

## The pattern worth naming first

Both tickets re-graded so far show the same failure, and it is not a clerical
one. A later comment declares "all N criteria MET" by grading against a locally
invented ID scheme that does not map one-to-one onto the ticket's own AC text,
and then treats that as closing the real ticket. `criteria-status.md` numbers
`CACHE.4a`/`4b` MET — but those rows are about cache-key dimensions, not about
the misattachment prevention that `CACHE.4` literally asks for, which is still
absent. The re-grade below is against the AC wording pulled live from Linear, not
against any local relabelling.

This is the same defect class as the stale stdio carve-out retired the same day:
a document that grades itself will always pass.

## MIK-7213 — cacheScope decision table and cache-key hardening

**5 of 8**, up from 2 of 8. Three ACs genuinely moved.

| AC | verdict | evidence | moved |
|---|---|---|---|
| CACHE.1 decision table exists | MET | `src/protocol/cacheable.rs:62-70`, `SCOPE_TABLE`, five rows | yes |
| CACHE.2 five endpoints return `ttlMs` + `cacheScope` | MET | `handlers.rs:1385-1433` with a total-coverage test over `CACHEABLE_METHODS` | no |
| CACHE.3 cache key carries the required dimensions | MET | `src/cache.rs:101-119` plus `support.rs:168-181`; nine dimensions, not the two the baseline found | yes |
| CACHE.4 misattachment structurally prevented | **ABSENT** | `CacheScope` (`cacheable.rs:22-27`) is a bare two-variant enum; `CacheableResult` exists only in a doc comment at `handlers.rs:1996` | no |
| CACHE.5 `tools/list` ordering byte-identical, tested | MET, narrowly | the test at `tests/mik_7213_acs.rs` calls the endpoint twice and passes — but `stable_tool_order()` (`prompt_cache.rs:162`) has zero production callers, so it passes because the fixed meta-surface builder is deterministic anyway | no |
| CACHE.6 hit rate measured before and after | **ABSENT** | `cache.rs:83` `hit_rate()` is pre-existing infrastructure, not a before/after number tied to ordering | no |
| CACHE.7 restricted key gets no more tools, tested | **ABSENT** | no test anywhere ties this change to tool count for a restricted key | no |
| CACHE.8 legacy callers unchanged | MET | `handlers.rs:1912,1965` inject cache fields only `if is_modern` | no |

CACHE.4 is the one that matters. The ticket was filed CRITICAL for exactly this
property, and what enforces it today is hand-review of a five-row table. Nothing
in the type system stops a future edit from marking a scoped endpoint `Public`.

CACHE.5 deserves its own note: **the test passes for the wrong reason.** The
mechanism the AC names is dead code, and the assertion is carried by an unrelated
determinism. Delete `stable_tool_order()` tomorrow and the test stays green.

## MIK-7215 — session-keyed inventory and stateless controls

**~3.5 of 7**, up from ~2.5. One AC moved half-way.

| AC | verdict | evidence | moved |
|---|---|---|---|
| SESSION.1 committed inventory table | MET | `RFC-0061`, grown from 12 rows to 18 | no |
| SESSION.2 six named features each verdicted | **PARTIAL** | firewall budgets, projection stickiness and routing profile are rows; "session sandbox" and "last-event-id resume" return zero hits in the RFC | no |
| SESSION.3 five reviewer categories verdicted | **ABSENT**, 0 of 5 | cancellation, progress reporting, backend affinity, subscription registration and token binding all return zero hits | no |
| SESSION.4 every row names a replacement | MET | sampled rows all carry a populated replacement column | no |
| SESSION.5 budgets survive two requests, one principal, no session | **PARTIAL** | the firewall half is real and keyed on principal: `security/firewall/mod.rs:580` wired at `:500`, tested at `:1566`. The sandbox half does not exist — `SandboxEnforcer::new` has no production call site | yes |
| SESSION.6 `Mcp-Session-Id` never emitted on 2026-07-28 | MET | `tests/mik_7215_acs.rs:417` | no |
| SESSION.7 table committed alongside RFC-0060 | **ABSENT** | the table lives only in RFC-0061; RFC-0060 still lists U7 as open at `:134,180` with no cross-reference, so a reader of RFC-0060 alone sees it unsolved | no |

## A half-wired type both tickets could lean on

`SessionLifecycle` (`src/gateway/session_lifecycle.rs`) is now half-wired: the
reaper has a real production call site (`server/mod.rs:1519`), and nothing in
`src/` ever calls `.register()` on it outside tests. The comment at
`server/mod.rs:1512-1514` says as much — "the write side that populates it is
wired separately". A reaper over an empty registry proves nothing, so no closing
claim should cite this type as evidence of a working lifecycle.

## A status note whose first sentence contradicts its own body

Recorded while looking for work on the core blockers. The `NFR.WORKLOAD.1` note in
`RELEASE-4.0.0-scope-status.json` opens with "the harness exists, is unmerged,
and has **NEVER BEEN EXECUTED**: zero measured runs, so every measurement
conjunct is harness-only", and grades all six conjuncts on that basis. Further
down, the same note records three executed runs, a located cause, a repaired
cache divergence, an admission wall and a current grade of INCONCLUSIVE with
measured spreads. The branch has moved seventeen commits past the revision the
opening sentence pins.

Both halves were written in good faith — the note is appended to as findings
land, and nobody rewrote the top. The hazard is that the opening sentence is
the part a reader quotes. Anyone skimming for "what is the state of the
workload harness" gets "zero measured runs" from a note that goes on to report
what those runs measured.

The row is `NFR.WORKLOAD.1`. An earlier draft of this section called it
`NFR.PERF.1`, which is a different row the note merely cites — `NFR.PERF.1`'s
absolute thresholds live in `tests/load/k6_gateway.js` and are untouched by the
workload harness.

The current state, from the note's own body: A/B/C grade INCONCLUSIVE at exit 2
because B and C spreads exceed the contract margins, and D/E are blocked on an
owner ruling rather than on measurement. Neither of those is "no runs exist".

## The whole scope, re-graded: 27 of 54

All nine in-scope tickets have now been re-graded against AC text pulled live
from Linear, at `a768d218`, read-only. MIK-6865's four criteria stay parked by
decision. This is the first count of the release scope that grades every ticket
against its own wording rather than against a requirement-document sample.

| ticket | baseline 2026-09-12 | re-graded | direction |
|---|---|---|---|
| MIK-7212 MRTR | ~0-1 of 9 | **3 of 9** | up, mostly baseline error |
| MIK-7213 CACHE | 2 of 8 | **5 of 8** | up, real |
| MIK-7214 HDR | 3 of 6 | **5 of 6** | up, via a different PR than claimed |
| MIK-7215 SESSION | ~2.5 of 7 | **3 of 7** | up slightly |
| MIK-7217 DISCOVER | 1 of 8 | **4 of 7** | up, real |
| MIK-7246 CONF | 2 of 4 | **4 of 4** | up, complete |
| MIK-7272 SPEC | 4 of 4 | **3 of 4** | **down** |
| MIK-7320 FIXTURE | 3 of 3 | **0 of 3** | **down** |
| MIK-7116 MIN | 0 of 6 | **0 of 6** | flat, reasoning corrected |

**27 of 54 met, 27 open.** MIK-7217's denominator is 7 rather than 8 because
`DISCOVER.2` names five separate repositories and is not gradable here.

Read the +9 carefully. Much of it is the baseline having missed work that was
already merged when it was written, not work done since — MIK-7212's largest
single move, `MRTR.7`, was graded FAIL on the claim of "zero production call
sites" that was already false on the baseline's own date. Two tickets moved
**down** on closer reading, and one of those, MIK-7320, went from a clean 3 of 3
to 0 of 3: its passing state depends on fixture files being committed rather
than on any code guard, and a skip branch that would have made the test honest
was added and then deliberately reverted.

Two grades stay INCONCLUSIVE pending a run, because the re-grade was read-only:
MIK-7320's `FIXTURE.3`, and the suite-green half of MIK-7214's `HDR.6`.

A targeted run at `54dc8e5e` — `mik_7217_acs`, `mik_7214_acs` and
`mik_7214_header_9_acs`, 73 tests, 0 failed, **0 ignored** — closes neither, and
the reason is worth stating rather than quietly banking the green. Both criteria
name the full `cargo test --all-features --no-fail-fast` suite; a three-binary
run under default features answers a narrower question. The feature gap is not
hypothetical: the same fixture suite reports 22 tests under `--all-features` and
32 without, so the two runs do not even cover the same rows. What the targeted
run does establish is that no `#[ignore]` is hiding inside those three files at
HEAD, and that the committed goldens still match.

`FIXTURE.1` stays PARTIAL regardless of any green. Its test panics
unconditionally when the fixture is missing, so it is green because four golden
files are committed, not because a guard holds — and the skip branch that would
have made that honest was added in `9c8fa8b3` and reverted in `ec633332`.

## Closing comments that cite evidence which is not there

The relabelling named at the top of this file is not the only way a ticket has
been made to read as closed. Two more patterns turned up, both verified:

- **MIK-7214's "20/20 rows MET"** cites line numbers that do not match its own
  cited source tree, and a branch, `fix/mrtr2-continuation-handle`, that is
  still not an ancestor of HEAD or main. The functionality is genuinely present
  — it arrived via an unrelated PR. The claim is right by accident.
- **MIK-7116's "13 tests"** is 11. The same ticket's baseline grade of "nothing
  exists" was also wrong on the day it was written: `tenant_guard.rs` and its
  test file predate it, and the grep that found nothing simply did not match
  `TenantGuard`.

The common failure is grading from a comment rather than from the cited
artefact. Every row above was graded by reading the artefact.

## Two flags outside any acceptance criterion

`docs/OWASP_AGENTIC_AI_COMPLIANCE.md:24` marks ASI09 **COVERED** and cites
`destructive_confirmation.rs`, whose own line 5 says it is "courtesy, not a
security control". A shipped compliance claim rests on a module that disclaims
the property. Nobody has recorded accepting that.

The dead-stdout defect is independently confirmed: `send_frame`
(`src/gateway/server/mod.rs:89`) does `drop(writer.send(frame).await)`, and
nothing stops the reader admitting calls whose responses are then discarded. No
delivery-reliability criterion should be graded MET while it stands.
