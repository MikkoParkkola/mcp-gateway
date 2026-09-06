# MRTR.8b in-flight lifetime — test plan (Change A only)

Status: draft, revision 1. Written before any test code exists.
Design: `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md` (revision 2).
Criterion: MRTR.8b — *in-flight exchange state MUST be bounded in lifetime and reclaimed on
abandonment* (`docs/requirements/RELEASE-4.0.0-criteria-status.md:140`).

Change B was withdrawn before any code, so this plan covers Change A alone. The three constraints
the earlier revision held for Change B (production-builder construction, an absent-section
negative, a cross-principal binding case) transferred to
`docs/design/2026-08-31-sub-4-idempotency-wiring.md` and are deliberately absent here — a plan for
a withdrawn change is the duplicate the withdrawal exists to avoid.

## What the plan asserts against

Change A adds `InFlight::guard(&self, now) -> MutexGuard<..>`, which takes the lock and reclaims
past-deadline records before returning it; `hold`, `route`, `complete` and `len` all read through
it, and the latter three gain a `now: u64` parameter.

Two clauses, and the second is where the criterion actually failed:

| clause | what it demands |
|---|---|
| C1 bounded lifetime | no reader observes a record whose deadline is at or before the `now` it supplied |
| C2 reclaimed on abandonment | an abandoned hold — one nobody ever completes — leaves the table without anyone scheduling a reclaimer |

The guarantee is **relative to the supplied `now`**, per the design's freshness paragraph. Row .07
asserts that limit rather than papering over it: a plan that asserted an absolute bound would be
asserting something the implementation does not deliver, and would go green anyway on any fixture
that captures its clock once.

## Rows

Level: U = unit, in `src/protocol/continuation.rs` tests. I = integration, in
`tests/mik_7212_acs.rs`, which drives `InFlight` from outside the crate.
Type: F = functional, B = boundary, N = negative.

| # | case | clause | level | type | RED comes from |
|---|---|---|---|---|---|
| .01 | `hold` an exchange with deadline T; `len(T+1)` reports 0 | C1 | U | F | `len` counts the dead today (`continuation.rs:756`) |
| .02 | same fixture; `route(key, T+1)` does not answer `Here` | C1 | U | F | `route` answers from presence alone (`:735-742`) |
| .03 | same fixture; `complete(key, T+1)` returns `false` | C1 | U | F | `complete` returns `true` for an expired entry today, telling the caller it completed something the table should not have held |
| .04 | live entry, deadline T; `len(T-1)` reports 1, `route(key, T-1)` answers `Here` | C1 | U | N | negative control: the reclaim must not eat live records. Fails if `guard` reclaims on `<` rather than `<=`, or on the wrong side of the comparison |
| .05 | hold, let the deadline pass, make NO intervening call, then one call through `guard`: the entry is gone on that first call | C2 | U | F | this is the abandonment case — nothing completes the exchange and no reaper exists |
| .06 | R2a's bargain, stated as a test: after the deadline passes with no intervening call the record is *still resident* in the map; residency ends at the first `guard`. Asserted via a direct map inspection, not a public reader | C2 | U | B | pins the honest bound. Fails if someone later adds a background reaper and quietly changes what the criterion means |
| .07 | freshness precondition: capture `now` once, hold with deadline `now+1`, advance nothing, call `route(key, now)` twice — the entry survives both, because the supplied `now` never moved | C1 | U | B | asserts the contract's limit. Fails if `guard` reads the wall clock internally, which is the rejected alternative |
| .08 | transferred from NFR.PERF.3 (`2026-09-01-nfr-perf3-reclamation.md:375-388`): `hold` at `IN_FLIGHT_CAPACITY` with expired entries present **admits** rather than refusing | C2 | U | B | today reclaim lives inside the capacity branch; after the change `hold` keeps only its refusal, so the reclaim must have happened in `guard` before the check reads `len` |
| .09 | `hold` at capacity with all entries live still refuses | C1 | U | N | the pair to .08. Without it, .08 passes trivially if the capacity refusal is deleted rather than re-ordered |
| .10 | the capacity walk is bounded by `IN_FLIGHT_CAPACITY = 4_096` (`continuation.rs:811`) and by nothing a client sizes: fill to capacity, assert the admitted count never exceeds it across a reclaim | C1 | U | B | pins the cost claim the design states as a number |
| .11 | end to end through the retry path: an abandoned exchange is not observable via `invoke.rs`'s `route` call at `:584` after its deadline, with the clock captured at `:545` driven forward | C1+C2 | I | F | proves the call sites were actually updated, not just the type. An external crate cannot see a `#[cfg(test)]` seam, which is why the clock is a real parameter |

Every criterion clause has a row; no cell is empty. C1 is carried by .01-.04, .07, .09-.11;
C2 by .05, .06, .08, .11.

## Q2 — can each case actually fail?

The plan-review question that a coverage map cannot ask. Three answers, none of them "it's a new
API so it won't compile":

**A compile error is not the RED we want.** `route`, `complete` and `len` gain a parameter, so
every row would fail to build before the change — a failure that proves nothing about behaviour.
The order that produces an honest red: land the signature change and `guard` **as a pass-through
that takes the lock and does not reclaim**, run the rows, and watch .01, .02, .03, .05, .08 and
.11 fail *on their assertions*. Then add the `reclaim_abandoned` call inside `guard` and watch
them go green. The pass-through step is a real intermediate state, not a ceremony: it is exactly
today's behaviour behind tomorrow's signature, so the assertion failures it produces are the
defect the criterion names.

**No fixture stages away the condition it observes.** The clock is a parameter, so a row that
advances time does it by passing a larger `now` — there is no sleep, no mock that could be
mis-wired to return a frozen instant, and no fixture that constructs the map in the state it
claims to observe. Row .06 inspects the map directly precisely because every public reader would
launder the answer through the reclaim it is trying to catch.

**Two rows exist only to stop their partners passing vacuously.** .04 fails if reclaim is too
eager; .09 fails if the capacity refusal is deleted instead of re-ordered. Both are cheap and both
have a concrete wrong implementation they catch.

## Not tested here, with reasons

- **R2 (wall-clock jump backwards).** Pre-existing, gates `hold` and the envelope check
  identically today, not made worse by this change. Testing it here would assert a behaviour this
  change neither introduces nor fixes.
- **R1 (a caller passing a stale or attacker-influenced `now`).** No caller derives `now` from
  input and the parameter is already public on `hold` (`:696`). The mitigation is the freshness
  sentence in `guard`'s doc comment; the observable half of R1 is row .07.
- **MRTR.10a reachability.** SUB.4's, with the caller-binding prerequisite that travels to it.
- **NFR.PERF.3 soak.** Its own slice; depends on Change A landing and on SUB.4 activating the
  cache.
