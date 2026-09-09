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

## The disconnect half of the criterion has no row, and the reason is structural

Both review legs asked for the *previously done by disconnect* half: one wanted a case proving state
survives a disconnect before its deadline, the other wanted a pin that disconnect cannot double-apply
cleanup alongside reap. Neither is buildable, for the same reason, and it is not an omission:
**the 2026 path has no disconnect.** `on_disconnect` gains no production caller under this change and
stays unreached deliberately (`...wiring.md:270-272`); the criterion exists precisely because the
transport close it fired on no longer happens (`:10-12`). A case staged around an event production
never emits is the fixture-replaces-production shape §P2 exists to reject, and a double-apply pin needs
two appliers where there is one.

The half that IS buildable — reclaimed state is still PRESENT before the deadline, and gone after — is
not a row either: it is two assertions inside T4, which already asserts presence at step 3 and absence
at step 5 on the anomaly entry itself.

## Q1, answered once: CONTROL.4 is a SINGLE criterion

`MIK-7215.CONTROL.4` is one acceptance criterion, not eight. **T4 is its case** — the row asserting the
reclaimed thing is gone. T1-T3 and T5-T8 are SUPPORTING cases covering the wiring T4 depends on, and T7's
*no test, by construction* is a stated reason for a DESIGN decision (D1a), never a criterion left without a
case. Row by row the table can be misread as eight criteria with one excused; it is one criterion, one case,
six supports and one compile-time obligation.

## The table

| ID | what it proves | level | type | how it can fail (Q2) |
|---|---|---|---|---|
| T1 | a request reaching `check_request` with a non-empty `control_identity` leaves a tracked entry keyed on that identity, whose deadline is `now + IDLE_TTL` | integration (handler) | positive / functional | the write site does not exist yet, so this fails by absence today — the free failure §P2 is built on. The fixture sets `control_identity` and `session_owner_key` to DELIBERATELY DIFFERENT values; without that discriminator the D3 key-provenance half of this row cannot fail, and a write site keyed on the wrong one ships green. After wiring, it also fails if the guard is inverted or the deadline is computed from the wrong base |
| T2 | an empty `control_identity` leaves NO entry | integration (handler) | negative | fails if the D4 guard is dropped. Cannot self-pass: the assertion is on an EMPTY map, so a fixture that accidentally tracks makes it red, not green. **Red today only by shared compile failure, and labelled below** — its own assertion cannot be reached until the write site T1 drives exists |
| T3 | `reap` returns the number of keys it removed | unit | contract change | `reap` returns `()` today, so the test cannot compile — that red proves the signature is absent, and no more. The criterion is the VALUE, not the type: an implementation returning a constant 0 compiles and passes the type check, so T3 owes the same falsifier probe as every other row. NOT a re-test of reap's removal logic, which is already covered |
| T4 | after a sweep, the reclaimed thing is GONE: the predecessor `last_tool` entry for the reaped identity is ABSENT from the anomaly detector | integration | functional — THE criterion | **this is the row the whole plan is for.** It fails if `on_session_end` was never registered, if the registered closure captured a `Weak` that is already dead, or if reap removed the key without firing handlers. It CANNOT be satisfied by an empty map: see the fixture rule below |
| T5 | the two constants the latency bound rests on are read where the design says: the write site reads `IDLE_TTL` (300s, D6) and the host tick reads `session_reaper_interval` from config (`streaming.rs:108`) | unit | boundary / constants | a wrong-by-10x constant passes every other row in this table while silently breaking the stated reclaim latency, because no other row reads either value. Fails if the write site hard-codes a literal, if it reaches for the unrelated shipped `PER_USER_IDLE_TTL` (`server/mod.rs:2131`) instead of D6's module constant, or if the tick uses a fixed interval rather than the configured one — which is what makes the streaming tests' 10-20 ms overrides work at all |
| T6 | the sweep log (D7) carries the COUNT of what it reclaimed, and is absent on an empty sweep | integration | observability / negative | two identities are reclaimed in ONE sweep; the case asserts exactly one event carrying the count 2, then drives a further tick over an empty map and asserts no event at all. Captured with a test-only `tracing` subscriber installed for the case — named here because a negative assertion with no stated capture mechanism cannot fail: it is green when nothing is captured, which is also green when nothing is emitted. The empty half needs a completion signal, and the sandwich an earlier draft of this row proposed does not supply one: two events with nothing between them is equally consistent with NO empty sweep having run at all, which is the same picture an unconditional `info!` would paint. So D7 now emits a `trace!` marker on EVERY sweep, empty or not, distinct from the conditional `info!` — named as a design event in D7 of the design. But a marker alone is not enough either, because the count-2 sweep emits one too: waiting for "a marker after the `info!`" catches that sweep's OWN marker and proves nothing about an empty map. So D7 fixes the ORDER as well as the emission — the marker is the LAST thing a sweep emits, after the conditional `info!`, which makes markers sweep boundaries and puts every `info!` before its own sweep's marker. The case CONSUMES the count-2 sweep's marker, then blocks on the NEXT one. That second marker can only have come from a LATER sweep, and by then the map is empty: it IS the acknowledgement that an empty sweep completed. The case then asserts NO `info!` was captured BETWEEN the two markers. An unconditional `info!` fails that assertion; a per-key `info!` makes the first event two events. Fails if the `info!` is unconditional (the per-tick-per-idle-gateway line D7 exists to prevent) and equally if it fires once per key, which a bare presence check would pass |
| T7 | every `spawn_reaper_on` call site supplies a lifecycle | — | **NO TEST, BY CONSTRUCTION** | D1a chose the parameter shape precisely so the COMPILER enforces this. A test asserting the compiler's own rule would be a test that cannot fail. Stated reason, per Q1 — not an empty cell |
| T8 | reap is unconditional: a key whose request is still in flight is still reaped | integration (host) | documented-behaviour pin | D5 deliberately has no in-flight guard; the tolerance is pushed onto what a handler may reclaim. It would fail against a future in-flight guard, and that guard would be added at the HOST call site, which is why the level is integration: a unit test on `reap` cannot see a guard placed in `streaming.rs`. At that level it cannot compile today — `spawn_reaper_on` takes no lifecycle argument — so its red is a compile red and its assertion is unproven until the wiring exists |

## The fixture rule T4 turns on (Q2, and the reason this plan was written before the tests)

T4's assertion is *absence*. An absence assertion passes trivially against a map that was never
populated — a fixture that forgets to build the predecessor entry produces a green test proving
nothing. So T4's arrangement is a precondition ASSERTION, not a setup step:

1. firewall feature compiled in, `enabled = true`, `anomaly_detection = true`, and the lifecycle handle
   obtained from `wire_session_lifecycle` (D8) — the production function that registers
   `Firewall::on_session_end`. The case registers NO handler of its own: a fixture that registers the
   thing under test proves the fixture;
2. drive a request so the anomaly detector writes a `last_tool` predecessor entry for the identity;
3. **assert that entry is PRESENT** — if this assertion fails, the test fails as a fixture error,
   loudly, rather than proceeding to a vacuous pass;
4. reclaim by STAGING, never by waiting: the tracked deadline is written already in the past, and the
   production host tick (~10 ms, as `streaming.rs:754`/`:786` already configure) sweeps over it. The case
   does NOT sleep for a tick and then assert — it BLOCKS until it observes the D7 sweep event for that
   sweep, on the same test-only `tracing` subscriber T6 installs, under a bounded wait that FAILS the case
   when no event arrives. A fixed sleep would let step 5 assert against a sweep that never ran, and an
   absence assertion is green when the tick was merely late and green when the tick never calls `reap` at
   all — the two failures this row exists to catch;
5. assert the entry is ABSENT.

### What T4 actually observes, since `last_tool` is private

`AnomalyDetector::last_tool` is a private `DashMap` (`anomaly.rs:50`); an integration test cannot read it.
The entry is observed INDIRECTLY, through the score `Firewall::check_request` returns (`anomaly_score:
Option<f64>`, `firewall/mod.rs:250`). Two branches of `score_transition` discriminate:

- vacant entry -> insert, return `0.5` (`anomaly.rs:154-158`);
- occupied entry -> `0.95` when the current tool is not a known successor of the recorded predecessor
  (`:171`).

The discriminant only holds if the tracker HAS data for that predecessor: with an untrained tracker
`predictions.is_empty()` returns `0.5` from the occupied branch too (`:166-168`), and present and absent
become indistinguishable. The fixture therefore trains the tracker it owns — `Firewall::new` takes the
`Option<Arc<TransitionTracker>>` (`firewall/mod.rs:310`), so the test holds the same `Arc` — with
`record_transition("sess-train", "srv:tool_a")` then `("sess-train", "srv:tool_b")`, giving `tool_a` a
known successor.

The probe is then the SAME call every time, `check_request(identity, "srv", "tool_a")`:

| call | state before | score | state after |
|---|---|---|---|
| step 2 | absent | 0.5 | present, predecessor `srv:tool_a` |
| step 3 (presence assertion) | present | 0.95 | present, predecessor unchanged |
| step 5 (absence assertion) | absent, if reclamation ran | 0.5 | present again |

Re-probing with `tool_a` rather than a third tool is what keeps the discriminant stable: any other tool
would be written back as the new predecessor, and a predecessor the tracker has no data for scores 0.5
whether the entry exists or not — a step-5 pass that proves nothing. The identity is a control identity
that is never reclaimed by anything but the sweep under test, which is what makes step 3's 0.95 an
assertion about presence rather than about the detector's mood.

Step 5's 0.5 has the same single-cause argument as the paragraph below: eviction cannot reach it, so an
absent entry means the registered handler ran.

Step 3 is the whole design of the case. Without it, T4 is the exact shape §P2 warns about: a test
that is green when the feature is compiled out, when the detector is disabled, and when the handler
was never registered — three ways to pass while proving nothing.

The absence at step 5 has exactly ONE possible cause, and saying so matters because the code contains a
second: the detector evicts an arbitrary entry once it is full (`src/security/firewall/anomaly.rs:138-139`).
That ceiling is `MAX_TRACKED_IDENTITIES = 100_000` (`:41`) and eviction additionally requires the incoming
key to be absent from the map, so a fixture holding two identities cannot construct it. The step-3 presence
assertion guards against a setup omission; this paragraph is what rules out a third-party removal between
steps 3 and 5. An absent entry therefore means the registered handler ran.

Note also what T4 does NOT assert: that `tracked_count` fell. `tracked_count` falls whether or not
any handler ran, so it observes the bookkeeping rather than the reclamation. Both review legs
converged on this and the design records it.

## No case waits 300 seconds, and none fabricates the number it is meant to prove

The host tick reads the wall clock (`SystemTime::now()` inside the tick, design :48, :69), so `now` is
not injectable at the level T4 runs at, and `IDLE_TTL` is 300 seconds against a 10-20 ms tick. A case
that literally measured the latency would either sleep for five minutes or inject its own `expires_at`
and then assert on the value it just supplied. Both were considered and both are rejected.

So the bound `[IDLE_TTL, IDLE_TTL + 1s + session_reaper_interval]` — the `1s` being the whole-second
comparison slack named below — is NOMINAL. It is not the equality the
first draft of this plan claimed, and it is not a guarantee either. Three things push past it and no
case in this table can bound any of them:

- `reap` compares whole seconds with a strict `>` (`session_lifecycle.rs:129`), so a deadline is
  reclaimed no earlier than the first whole second PAST it — up to ~1s of slack before the window starts;
- the tick is a scheduled task on a shared runtime, so its period is a floor, not a promise: under load
  a sweep arrives late by an amount nothing here measures;
- `SystemTime` is wall-clock and not monotonic, so an NTP step or a suspend moves the deadline itself
  after it was written.

What this plan asserts, and all it asserts, is the composition below — that each ingredient of the bound
is the value the design names. The bound holds on a quiet clock and an unloaded runtime; it is a NOMINAL
figure for capacity planning, never a timing guarantee a test enforces. Each ingredient is pinned
somewhere cheaper:

| the fact | where it is pinned |
|---|---|
| the write site computes `expires_at = now + IDLE_TTL` | T1, at the write site, on real arithmetic |
| `reap(now)` removes exactly the keys whose deadline has passed | the 3 shipped lifecycle tests (§P0 OUT) |
| the host tick actually calls `reap` | T4 — a deadline already in the past is reclaimed on the first sweep that observes it |
| both constants are the ones the design names | T5 |

T4's past deadline is a STAGING device for *the tick calls reap*; it makes no latency claim, so it is not
a fixture asserting on its own input. The latency claim rests on T1 and T5, where the numbers live.

## Levels and types present

V-model levels: unit (T3, T5), integration (T1, T2, T4, T6, T8), compile-time (T7).
Types: positive (T1), negative (T2, T6), contract change (T3), functional (T4), boundary/constants
(T5), observability (T6), documented-behaviour pin (T8). No case is a happy-path duplicate of
another, which is what the plan-before-tests order buys — tests written from a design inherit the
design's happy path.

## Which rows get the free failure, and the one that does not

Per row, because one row breaks the blanket claim the first draft made.

**Red BY COMPILE and red BY ASSERTION are different evidence, and every row here is the first kind.**
A case that names surface which does not exist yet does not fail its assertion — it fails to compile, and a
compile error is ONE error for the whole file. The assertion is never evaluated, so the red proves the
SURFACE IS ABSENT and says nothing about whether the assertion could discriminate. An earlier revision of
this paragraph said T1, T4, T5 and T6 "fail by absence today — the free failure §P2 is built on", which
reads as an assertion red and is wrong in exactly the way T2's label was wrong, two paragraphs down.

| row | red today | what that red proves |
|---|---|---|
| T1 | compile | the write site and the lifecycle handle it needs do not exist |
| T2 | compile, shared with T1 | nothing T1's red does not already prove |
| T3 | compile | `reap` returns `()`. The SIGNATURE is absent; whether the assertion can tell a right count from a wrong one is untested, exactly as elsewhere |
| T4 | compile | `wire_session_lifecycle` (D8) does not exist |
| T5 | compile | `IDLE_TTL` does not exist |
| T6 | compile | the D7 marker and the handle do not exist |
| T8 | compile | `spawn_reaper_on` takes no lifecycle argument |

T8's earlier label — "fails on its own assertion" — does not survive this either: at integration level it
drives a production tick whose signature it cannot yet name. T7 has no test at all, by construction.

**The consequence is a step, not a caveat.** For every row above — T3 included, its earlier exemption
withdrawn — the assertion is UNPROVEN until the wiring exists. So at green time each row gets one
falsifier probe (§P2's retrofitting
mechanism, the `mktemp`/`trap` recipe): break the single operand the row exists to pin — the D4 guard
polarity for T2, the constant for T5, the returned count for T3 and T6, the `register` call for T4, the
host's `reap` call for T8 — and observe THAT row go red ON ITS OWN ASSERTION. A row that stays green
under its own probe was never a test. No coverage measurement can see this, and nothing else in this
plan can either.

**T2's label was wrong, and the correction is a downgrade of its evidence, not an upgrade.** An
earlier revision said T2 "is green the moment it is written" and filed it as one of the two survivors
`test-plan-honesty` names — a case that can never go red now. Both halves are false. T2 shares a
compilation unit with T1: to assert that an empty `control_identity` leaves NO entry, it must drive the
same handler entry point T1 drives, and that entry point does not exist. The file does not compile, so
T2 is red today for exactly the reason T1 and T3 are — a compile error is ONE error for the whole file,
and T2 contributes no independent evidence to the red observation. Nothing is proved by its redness
that T1's does not already prove.

Once the write site exists the case becomes real: it goes red against a write site that tracks the empty
key, which is the D4 guard it exists to pin. So T2 is red-capable, just not independently red TODAY.
The honest statement is the narrow one — its red is shared, its green is deferred, and it owes its
falsifier probe at green time like every other row. The probe is not about fixing anything: it breaks
the D4 guard polarity T2 pins and requires T2 to go red on its own assertion.

**T8's level moved twice and its red label had to move with it, to compile.** An earlier revision carried
T8 as a unit case on `reap` and labelled it green-today; that label did not survive the level change to
integration (host). The label that replaced it — "fails on its own assertion" — does not survive either.
At the host level the case drives the PRODUCTION tick, and that tick cannot yet be driven with a lifecycle
at all: `spawn_reaper_on` takes no lifecycle argument, so the file does not compile. What is TRUE today is
the weaker fact behind both labels: `reap` has no production caller, its three call sites all sitting inside
its own `#[cfg(test)]` module (`session_lifecycle.rs:180`, `:188`, `:209`). That is why the case is worth
writing, and it is not evidence the assertion discriminates. The classification follows the level; changing
one without re-deriving the other is how a table ends up claiming a red that no revision can produce.

## Coverage bar and the one risk (DoD §4)

Coverage target for this change, qualitative because the wiring is a handful of lines in three files: both
constants' readers (T5), both polarities of the D4 identity guard (T1, T2), the registered consumer actually
firing (T4), the host tick's call (T4), and reap's new return value (T3). A line-coverage percentage over
three call sites would be a number without a claim behind it.

One risk, and it is the one both review legs found: TIMING DETERMINISM. It is addressed by removing the need
for a clock seam entirely — see the composition table above — not by tolerating a flaky sleep.
## The green record — NOT DISCHARGED

The RED table above records why each row failed before the implementation existed.
That failure was free: the code was not there. The other half — re-checking each row
against a deliberately reintroduced defect, so a row that cannot fail is visible as
one — was attempted and **did not produce usable evidence**. It is recorded here as an
open obligation rather than as a result, because the run has three defects that each
independently break attribution:

- **The restore leg never ran.** Its backups were written to a scratch directory that
  did not survive, so every restore reported failure and no defect was removed before
  the next was added. Defects therefore *accumulated*: T5 ran against its own operand,
  T3 against T5's as well, and T2/T6/T8 against three or more. No row after the first
  has a RED attributable to the operand it names.
- **No failure reason was read.** Probe stdout was discarded, so what each row actually
  reported was never seen. This plan's own rule (§P2, the retrofitting exception) is
  that a compile error is not a caught defect — and with an accumulating set of edits,
  a compile error is the likeliest thing a later probe hit.
- **The source was left corrupted.** Three injected defects (`from_secs(301)`,
  `let reclaimed = 0;`, and a stubbed `wire_session_lifecycle` body) were still live in
  a shared worktree after the run and were repaired by hand. Any red a peer session saw
  in `mik_7215_control4_*` during that window is phantom.

What the implementation *does* have: T1's red-then-green, observed live during
implementation on the assertion text itself ("not reclaimed at its deadline: the write
site used a longer TTL"), and all seven rows green against the repaired source with
every operand re-verified in the file. That is the evidence CONTROL.4 rests on. The
probe record is not part of it.

### The obligation, deferred (§P1 four fields)

| field | value |
|---|---|
| owner | MIK-7215, the next session to touch `session_lifecycle` |
| what would resolve it | one probe per row, in an isolated checkout, each with its own restore verified by re-running the row to green before the next defect is injected, and each probe's failure text read rather than discarded |
| when | before the 4.0.0 release tag, or on the next change to any CONTROL.4 operand |
| if it resolves badly | a row that stays green with its operand broken is a test that does not test; that row is rewritten and this plan's table amended, which does not move CONTROL.4's wiring evidence |

Nothing in this change depends on the deferred answer: the criterion is met by the
wiring plus seven green tests, and the probe pass would only strengthen confidence in
the tests themselves.

Two constraints for whoever runs it, learned the expensive way: **do not run mutating
probes in a shared worktree** — peers run the same suite and will diagnose an injected
defect as their own regression — and **keep the only copy of the source out of scratch
storage**, which is how this run lost its restores.
