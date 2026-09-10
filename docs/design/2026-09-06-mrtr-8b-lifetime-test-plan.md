# MRTR.8b in-flight lifetime — test plan (Change A only)

Status: draft, revision 1. Written before any test code exists.
Design: `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md` (revision 2).
Criterion: MRTR.8b — *in-flight exchange state MUST be bounded in lifetime and reclaimed on
abandonment* (`docs/requirements/RELEASE-4.0.0-criteria-status.md:140`).

Change B was withdrawn before any code, so this plan covers Change A alone. Two of the three
constraints the earlier revision held for Change B (production-builder construction, a
cross-principal binding case) transferred to
`docs/design/2026-08-31-sub-4-idempotency-wiring.md` and are deliberately absent here — a plan for
a withdrawn change is the duplicate the withdrawal exists to avoid. The third — an absent-section
negative — went nowhere on purpose: SUB.4 has no optional `idempotency.enabled` section to be
absent, so transferring it would smuggle back the kill switch the withdrawal removed.

## What the plan asserts against

Change A adds `InFlight::guard(&self, now) -> MutexGuard<..>`, which takes the lock and reclaims
past-deadline records before returning it; `hold`, `route`, `complete` and `len` all read through
it, and the latter three gain a `now: u64` parameter.

Two clauses, and the second is where the criterion actually failed:

| clause | what it demands |
|---|---|
| C1 bounded lifetime | no reader observes a record whose deadline is **strictly before** the `now` it supplied: reclaimed when `now > deadline`, live while `now <= deadline` |
| C2 reclaimed on abandonment | an abandoned hold — one nobody ever completes — leaves the table without anyone scheduling a reclaimer |

The predicate is not a detail the plan may leave to the implementation. Three surfaces already
compare a deadline to a `now` and all three agree at equality: `reclaim_abandoned` retains while
`now <= *deadline` (`continuation.rs:676`), `Keyring::open` refuses only when `now > expires_at`
(`:508`), and `Consumed::consume` retains on the same `now <= *deadline` (`:605`). An entry is
therefore **live at its own deadline**, and a `guard` that reclaimed at `deadline == now` would
drop a record the envelope still accepts. Row .04a is the only row that sits on that boundary.

The guarantee is **relative to the supplied `now`**, per the design's freshness paragraph. Row .07
asserts that limit rather than papering over it: a plan that asserted an absolute bound would be
asserting something the implementation does not deliver, and would go green anyway on any fixture
that captures its clock once.

## Rows

Level: every row below is U = unit, in `src/protocol/continuation.rs` tests. **No row is at
integration level**, and that is a finding rather than an omission — see the first entry under
*Not tested here*: the envelope refuses an expired retry before the retry path ever reaches the
table, so an integration row would observe `Keyring::open`, not the reclaim.
Type: F = functional, B = boundary, N = negative.

Every row's `now` is a value the test passes. All of them are anchored to **one synthetic epoch
`T`** — a fixed second count far from the wall clock (`T = 1_000`, matching the small literals the
existing suites already use) — never `SystemTime::now()`. The epoch is not decoration: it is the
only thing that lets row .07 tell a `guard` that reads the clock from one that does not, because a
fixture built on the real clock answers identically under both.

Two existing suites already construct `InFlight` and will need their call sites updated with the
new `now` parameters: `tests/mik_7212_acs.rs` `mod inflight` (`:434`, tables built at `:441`,
`:486`, `:496`, `:510`, `:538`, and MRTR.8's own bounded-table and abandonment cases at `:491` and
`:509`), and `tests/mik_7212_mrtr_component_acs.rs` (`:1107`, `:1131`, `:1234`, `:1304`).
Revision 1 excluded the first on a grep for `in_flight`; the module is spelled `inflight` and the
exclusion was false. Note also that capacity is a constructor argument
(`InFlight::new("gw-1", 4)`), not the constant — so a capacity row is written at 4, never at
4_096.

| # | case | clause | level | type | RED comes from |
|---|---|---|---|---|---|
| .01 | `hold` an exchange with deadline T; `len(T+1)` reports 0 | C1 | U | F | `len` counts the dead today (`continuation.rs:756`) |
| .02 | same fixture; `route(key, T+1)` does not answer `Here` | C1 | U | F | `route` answers from presence alone (`:735-742`) |
| .03 | same fixture; `complete(key, T+1)` returns `false` | C1 | U | F | `complete` returns `true` for an expired entry today, telling the caller it completed something the table should not have held |
| .04 | live entry, deadline T; `len(T-1)` reports 1, `route(key, T-1)` answers `Here`, and `complete(key, T-1)` returns `true` — identity, since a count of 1 could be the wrong record | C1 | U | N | negative control: the reclaim must not eat live records. Fails if `guard` reclaims eagerly on a clearly-live entry — an inverted `retain` predicate, or a comparison on the wrong side |
| .04a | entry with deadline T; `len(T)` reports 1, `route(key, T)` answers `Here`, and `complete(key, T)` returns `true` | C1 | U | B | the boundary, and the ONLY `now` at which `<` and `<=` differ — .01 (`T+1`) and .04 (`T-1`) pass under either. Fails if `guard` reclaims at `deadline == now`, which would drop a record `Keyring::open` still accepts (`continuation.rs:508`) |
| .05 | hold, let the deadline pass, make NO intervening call, then one call through `guard`: the entry is gone on that first call. **Table-driven over all four public readers** — `hold`, `route`, `complete`, `len` — each in its own fresh fixture, so C2 is not as strong as whichever single method an implementer picked | C2 | U | F | this is the abandonment case — nothing completes the exchange and no reaper exists |
| .06 | R2a's bargain, stated as a test: after the deadline passes with no intervening call the record is *still resident* in the map; residency ends at the first `guard`. Asserted by inspecting the map directly *before* any `guard`
call, not through a public reader — which is why it does not contradict .05, whose assertion is made
*after* one | C2 | U | B | pins the honest bound. Fails if someone later adds a background reaper and quietly changes what the criterion means |
| .07 | freshness precondition: hold with deadline T, advance nothing, call `route(key, T-1)` twice — the entry survives both, because the supplied `now` never moved | C1 | U | B | asserts the contract's limit, and the synthetic epoch is what makes it assertable: with a real-clock fixture (`now` from `SystemTime::now()`, deadline `now+1`) a `guard` that read the clock internally would answer identically and the row could not fail for its stated reason. Anchored at T = 1_000, a wall-clock `guard` sees a `now` ~1.7 billion seconds past the deadline, reclaims, and `route` answers `Gone` |
| .08 | transferred from NFR.PERF.3 (`2026-09-01-nfr-perf3-reclamation.md:375-388`): `hold` at capacity with expired entries present **admits** rather than refusing. Run at `InFlight::new("gw-1", 4)`, as `tests/mik_7212_acs.rs:496`/`:510` already do — the falsifier is identical at 4 and at 4_096, and inserting 4_096 entries would not make the walk observable. The design's cost number gets its own one-line same-module assertion, `IN_FLIGHT_CAPACITY == 4_096` (`continuation.rs:811`, private to the crate), which pins the documented bound without pretending a test can see a walk length | C2 | U | B | today reclaim lives inside the capacity branch; after the change `hold` keeps only its refusal, so the reclaim must have happened in `guard` before the check reads `len` |
| .09 | `hold` at capacity (4) with all entries live still refuses | C2 | U | N | the pair to .08. Without it, .08 passes trivially if the capacity refusal is deleted rather than re-ordered |

Every criterion clause has a row; no cell is empty. C1 is carried by .01, .02, .03, .04, .04a and
.07; C2 by .05, .06, .08 and .09. Rows .10 and .11 were deleted in review — .11 because the
envelope refuses before the table is consulted (below), .10 because it asserted occupancy, which
.09 already asserts, while the walk length it claimed to pin is not observable through any public
reader. Neither clause lost its last row: eliminating a row that cannot fail is not a coverage
cut.

## Q2 — can each case actually fail?

The plan-review question that a coverage map cannot ask. Three answers, none of them "it's a new
API so it won't compile":

**A compile error is not the RED we want.** `route`, `complete` and `len` gain a parameter, so
every row would fail to build before the change — a failure that proves nothing about behaviour.
The order that produces an honest red: land the signature change and `guard` **as a pass-through
that takes the lock and does not reclaim**, run the rows, and watch .01, .02, .03, .05, .06 and
.08 fail *on their assertions*. Then add the `reclaim_abandoned` call inside `guard` and watch
them go green. The pass-through step is a real intermediate state, not a ceremony: it is exactly
today's behaviour behind tomorrow's signature, so the assertion failures it produces are the
defect the criterion names.

**No fixture stages away the condition it observes.** The clock is a parameter, so a row that
advances time does it by passing a larger `now` — there is no sleep, no mock that could be
mis-wired to return a frozen instant, and no fixture that constructs the map in the state it
claims to observe. Row .06 inspects the map directly precisely because every public reader would
launder the answer through the reclaim it is trying to catch.

**Four rows never go RED, and that is correct rather than a gap.** Membership is decided
mechanically, not by taste: a row is in this set if it is green under the pass-through *and* green
after the reclaim lands. That leaves .04, .04a, .07 and .09. The other six — .01, .02, .03, .05,
.06, .08 — fail on their assertions at the pass-through step and go green when `reclaim_abandoned`
moves into `guard`; .06 belongs with them because its second half, *residency ends at the first
`guard`*, is exactly what the pass-through does not do.

A row whose RED never arrives is a defect when it is the only evidence for a clause. Neither clause
depends on one here: C1's red comes from .01-.03, C2's from .05, .06 and .08. So the four are
guards, and each names a concrete wrong implementation it catches — .04 an over-eager reclaim
anywhere, .04a an over-eager reclaim at exactly the deadline (the one `now` .04 cannot see), .07 a
`guard` that reads the wall clock, .09 a capacity refusal deleted rather than re-ordered. Their
falsifier is the wrong implementation, not the absent one, so each is verified by writing that
implementation and watching the row fail — never by waiting for a red that correct code would have
to produce. That verification is a real step, not a figure of speech: revision 1 asserted it of
.07 while .07's fixture made it impossible, which is what this review caught.

## Not tested here, with reasons

- **An end-to-end row through the retry path.** There is none, and the reason is a source fact
  rather than a scheduling one. `invoke.rs` captures `now` at `:546` and hands it to
  `Keyring::open` at `:547`, which refuses with `Expired` exactly when `now > payload.expires_at`
  (`continuation.rs:508`) — *before* control ever reaches the `route` call at `:584`. The two
  deadlines are the same number: `hold(&backend_id, expiry_for(now), now)` feeds `expiry_for(now)`
  to the table and to the minted envelope in one expression (`continuation.rs:864`). So on the
  retry path the envelope refuses first, always, and the table's reclaim changes nothing a caller
  can observe. Revision 1 carried row .11 asserting exactly that observation; it was deleted rather
  than restated, because a row that cannot fail for the reason it names is the defect a plan review
  exists to find. The consequence is a design fact, not a test gap, and is recorded in the design:
  **MRTR.8b's reclaim buys capacity, not routing behaviour** — the payoff is that an abandoned
  exchange stops occupying a slot, which is what rows .08 and .09 assert.

- **R2 (wall-clock jump backwards).** Pre-existing, gates `hold` and the envelope check
  identically today, not made worse by this change. Testing it here would assert a behaviour this
  change neither introduces nor fixes.
- **R1 (a caller passing a stale or attacker-influenced `now`).** No caller derives `now` from
  input and the parameter is already public on `hold` (`:696`). The mitigation is the freshness
  sentence in `guard`'s doc comment; the observable half of R1 is row .07.
- **MRTR.10a reachability.** SUB.4's, with the caller-binding prerequisite that travels to it.
- **NFR.PERF.3 soak.** Its own slice; depends on Change A landing and on SUB.4 activating the
  cache.

## Evidence

Per DoR E1-E4 and the V/I/A marking rule — V = two or more independent sources, I = one, A = none.

| claim | mark | source |
|---|---|---|
| an entry is live *at* its deadline; reclaim is `now > deadline` | **V** | three independent surfaces agree at equality: `reclaim_abandoned` retains on `now <= *deadline` (`continuation.rs:676`), `Keyring::open` refuses only on `now > expires_at` (`:508`), `Consumed::consume` retains on `now <= *deadline` (`:605`) |
| the envelope refuses an expired retry before `route` is reached | **V** | the order in `invoke.rs` (`:546`, `:547`, `:584`) and the shared `expiry_for(now)` at `continuation.rs:864` |
| `len` has no production consumer; its only non-test caller is `is_empty` | I | `continuation.rs:756`, `:762` — one file read |
| `IN_FLIGHT_CAPACITY = 4_096`, private, used once at construction | I | `continuation.rs:811`, `:836` |
| `InFlight` is constructed by two external suites, capacity as a constructor argument | I | `tests/mik_7212_acs.rs:434` ff., `tests/mik_7212_mrtr_component_acs.rs:1107` ff. |
| `complete` returns `true` today for an entry whose deadline has passed | I | `continuation.rs:735-742` and the absence of any deadline read on that path |

No claim in this plan is unmarked, and none is A.

**One property is claimed in prose and asserted nowhere, deliberately.** The walk `reclaim_abandoned`
performs is bounded by `IN_FLIGHT_CAPACITY`, and the plan says so; what the suite asserts is the
literal `IN_FLIGHT_CAPACITY == 4_096`, which pins the constant, not the walk. No public reader
exposes a walk length, so no honest row can observe it — row .10 tried and was deleted for exactly
that. Recorded here rather than left implicit, because a property stated in prose with no assertion
behind it is the gap a plan review exists to name.
