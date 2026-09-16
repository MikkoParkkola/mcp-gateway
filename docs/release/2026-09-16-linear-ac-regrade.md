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

Recorded while looking for work on the core blockers. The `NFR.PERF.1` note in
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

The current state, from the note's own body: A/B/C grade INCONCLUSIVE at exit 2
because B and C spreads exceed the contract margins, and D/E are blocked on an
owner ruling rather than on measurement. Neither of those is "no runs exist".
