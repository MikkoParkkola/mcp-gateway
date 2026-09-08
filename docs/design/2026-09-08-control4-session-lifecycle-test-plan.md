# CONTROL.4 — §P2 test plan (TABLE FIRST, no test code yet)

Criterion: `MIK-7215.CONTROL.4` — *session-lifecycle TTL-reaping owns cleanup previously done by
disconnect*. Design: `docs/design/2026-09-08-control4-session-lifecycle-wiring.md` (D1-D7, dual
review passed, closure pass SHIP).

This document exists to be reviewed BEFORE any test is written. Per `development-process.md` §P2 a
plan review answers two questions and only a plan review can ask them:

- **Q1 — does every criterion have a case, or a stated reason it has none?** An empty cell is the
  finding, not an omission to be tidied later.
- **Q2 — can each named case actually FAIL?** A case whose fixture makes its own assertion true, or
  whose staging removes the condition it observes, passes every coverage tool ever built. The
  `how it fails` column is therefore not decoration — it is the column the review is for.

## Scope of this plan (§P0)

FOR: the wiring introduced by this change — the write site, the host loop's reap call, the
registered consumer, and the two constants' actual readers.
OUT: `SessionLifecycle`'s own already-shipped mechanics. `register`, `track`, `untrack`, `reap`,
`on_disconnect` and `fire_cleanup` are covered by `tests/mik_7215_controls_acs.rs mod lifecycle`
(3 tests, passing against the real type). Re-testing them here would be a second copy that drifts.
The ONE exception is called out in T3 and it is a genuine behaviour change, not a re-test.

## The table

| ID | what it proves | level | type | how it can fail (Q2) |
|---|---|---|---|---|
| T1 | a request reaching `check_request` with a non-empty `control_identity` leaves a tracked entry whose deadline is `now + IDLE_TTL` | integration (handler) | positive / functional | the write site does not exist yet, so this fails by absence today — the free failure §P2 is built on. After wiring, it fails if the guard is inverted, if the deadline is computed from the wrong clock (D2), or if the key is `session_owner_key` rather than the re-derived `control_identity` (D3) |
| T2 | an empty `control_identity` leaves NO entry | integration (handler) | negative | fails if the D4 guard is dropped. Cannot self-pass: the assertion is on an EMPTY map, so a fixture that accidentally tracks makes it red, not green |
| T3 | `reap` returns the number of keys it removed | unit | contract change | `reap` returns `()` today. The test cannot compile against the current signature — a compile failure IS the red, and it is honest because the signature change is the point. NOT a re-test of reap's removal logic, which is already covered |
| T4 | after a sweep, the reclaimed thing is GONE: the predecessor `last_tool` entry for the reaped identity is ABSENT from the anomaly detector | integration | functional — THE criterion | **this is the row the whole plan is for.** It fails if `on_session_end` was never registered, if the registered closure captured a `Weak` that is already dead, or if reap removed the key without firing handlers. It CANNOT be satisfied by an empty map: see the fixture rule below |
| T5 | reclaim latency is `IDLE_TTL + session_reaper_interval`, not `IDLE_TTL` | integration | boundary / timing | fails if the entry is gone at the tick BEFORE the deadline (deadline arithmetic wrong) or still present two ticks after (reap not called on the host loop at all). The existing streaming tests already run this loop at 10-20 ms (`streaming.rs:754`, `:786`), so the case is fast and deterministic without a sleep-and-hope |
| T6 | the sweep log (D7) is emitted when something was reclaimed and NOT when nothing was | integration | observability / negative | fails if the `info!` is unconditional — which is the defect D7 exists to prevent, a log line per tick per idle gateway |
| T7 | every `spawn_reaper_on` call site supplies a lifecycle | — | **NO TEST, BY CONSTRUCTION** | D1a chose the parameter shape precisely so the COMPILER enforces this. A test asserting the compiler's own rule would be a test that cannot fail. Stated reason, per Q1 — not an empty cell |
| T8 | reap is unconditional: a key whose request is still in flight is still reaped | unit | documented-behaviour pin | D5 deliberately has no in-flight guard, and the tolerance is pushed onto what a handler may reclaim. Pinning it stops a later author "fixing" it into a generation counter — the second mechanism D3a was deleted for. Fails if someone adds that guard |

## The fixture rule T4 turns on (Q2, and the reason this plan was written before the tests)

T4's assertion is *absence*. An absence assertion passes trivially against a map that was never
populated — a fixture that forgets to build the predecessor entry produces a green test proving
nothing. So T4's arrangement is a precondition ASSERTION, not a setup step:

1. firewall feature compiled in, `enabled = true`, `anomaly_detection = true`;
2. drive a request so the anomaly detector writes a `last_tool` predecessor entry for the identity;
3. **assert that entry is PRESENT** — if this assertion fails, the test fails as a fixture error,
   loudly, rather than proceeding to a vacuous pass;
4. advance past the deadline, let one sweep run;
5. assert the entry is ABSENT.

Step 3 is the whole design of the case. Without it, T4 is the exact shape §P2 warns about: a test
that is green when the feature is compiled out, when the detector is disabled, and when the handler
was never registered — three ways to pass while proving nothing.

Note also what T4 does NOT assert: that `tracked_count` fell. `tracked_count` falls whether or not
any handler ran, so it observes the bookkeeping rather than the reclamation. Both review legs
converged on this and the design records it.

## Levels and types present

V-model levels: unit (T3, T8), integration (T1, T2, T4, T5, T6), compile-time (T7).
Types: positive (T1), negative (T2, T6), contract change (T3), functional (T4), boundary/timing
(T5), observability (T6), documented-behaviour pin (T8). No case is a happy-path duplicate of
another, which is what the plan-before-tests order buys — tests written from a design inherit the
design's happy path.

## Retrofitting: not applicable, and why that is worth one line

Every case above tests wiring that does not exist yet, so each gets the free failure. The falsifier
probe (§P2's recovery mechanism for tests written after the code) is NOT needed here and its absence
is not an omission. T3 is the closest call — `reap` exists — but its assertion is on a return value
the current signature cannot produce, so it fails to compile rather than passing hollowly.
