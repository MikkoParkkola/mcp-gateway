<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# NFR.PERF.3 — reclamation, and the one table that cannot currently reclaim

`NFR.PERF.3` (`docs/requirements/RELEASE-4.0.0-requirements.md:232`), verbatim: *"Memory MUST NOT
grow unboundedly with abandoned continuations; a soak with abandonment MUST show reclamation."*

Two clauses, and they are not the same clause. **Bounded** and **reclaiming** are different
properties, and a table can satisfy the first while failing the second in the way that matters: it
stops growing because it stops working. That distinction is the whole design.

## What is actually on the live path

`ContinuationState` is constructed in production — `src/gateway/meta_mcp/mod.rs:401`, reaching the
router through `server/mod.rs:1175`. So it is not a tests-only type. But **constructed is not
called**, and for `InFlight` the distinction is the whole story: `rg '\.in_flight|\.hold\(|\.route\(' src/`
outside tests returns the accessor's own definition (`continuation.rs:774`) and nothing else — no
production code calls `hold`, `route` or `complete`. The table is allocated on the live path and
exercised only by tests.

Two things follow, and the second is the one a release gate has to hear.

The defect below is **latent, not currently manifesting**: nothing wedges today because nothing
holds. That is why this is a design and not an incident.

And `NFR.PERF.3` cannot be closed by this soak alone. A component soak proves the table reclaims;
it does not prove the production path reaches the table. Closure needs both — this soak, *and*
evidence that `MRTR.6` wiring calls `hold` on a live request. Certifying reclamation on a
dormant component is exactly the "green metric, dead path" failure this document is otherwise
about, one level up. `MRTR.7` is not part of that closure: `InFlight` holds exchanges open on behalf
of a legacy backend (`continuation.rs:578`), which is the `MRTR.6` direction, and the modern-backend
side of `MRTR.7` never reaches this table.

| surface | bound | reclaims on the live path? |
|---|---|---|
| `ConsumedLedger` (`continuation.rs:484`, capacity 65 536) | refuses at capacity | **yes** — `consume` retains over deadlines *before* refusing (`:527-533`) |
| `InFlight` (`:595`, capacity 4 096) | refuses at capacity | **no** — `hold` (`:619-621`) returns `None` at capacity and reclaims nothing |
| `Keyring` | fixed at construction | n/a |

`rg 'reap\(|evict_expired\(' -g '*.rs'` returns, for these two types, matches in `tests/` only:
`tests/mik_7212_acs.rs:270`, `:299`, `:461`, and `tests/mik_7215_controls_acs.rs:143`. The same
command also hits `src/cache.rs:188` and `:423` — an unrelated `Cache::evict_expired` that is called
from its own live path and is not this subsystem. **Both continuation reclaimers are called
exclusively from tests.** The ledger survives that because it does not need its reclaimer —
`consume` reclaims inline. `InFlight` has no such path, and that is the defect.

## The failure this produces is a wedge, not a leak

Memory is bounded either way: 4 096 entries is the ceiling and the process cannot exceed it. So the
first clause of `NFR.PERF.3` is met by the existing capacity check, and a naive soak measuring RSS
would pass.

What happens instead is worse than a leak and invisible to that soak. A client is *permitted* to
start an elicitation and never retry — the specification says so, and `InFlight`'s own doc comment
at `:653-656` calls abandonment "the common case, not the exceptional one". Every abandoned
exchange holds its slot until its deadline passes **and something calls `reap`**. Nothing does. So
the occupied count is monotonic over the life of the process: it rises with abandonment, never
falls, and on reaching 4 096 the gateway refuses every subsequent legacy elicitation forever, with
a capacity error naming a table whose entries all expired hours ago.

That is the second clause failing. There is no reclamation, so a soak with abandonment cannot show
any — which is precisely the observation the criterion asks the soak to make.

## `MRTR.8` says "count **and lifetime**", and those need different mechanisms

`MIK-7212.MRTR.8` (`docs/requirements/RELEASE-4.0.0-requirements.md:144`), verbatim: *"State held
for an in-flight exchange MUST be bounded in count **and lifetime**"*. An earlier revision of this
document read the criterion as one obligation and answered it with one mechanism — an inline retain
at capacity — while explicitly rejecting a periodic reaper as "the obvious answer and the wrong
one". That reading was wrong, and the word it missed is `lifetime`.

**Design event, named as one** (`development-process.md` §P3): this reverses a rejection this
document previously argued for. It is recorded rather than quietly rewritten because the rejection
was the load-bearing claim of the section it replaces.

Pressure-triggered reclamation bounds *count* and nothing else. On a gateway that never reaches
4 096 concurrent exchanges — which is every gateway, most of the time — no `hold` is ever refused,
so the retain never runs, and an entry abandoned at 09:00 with a 30-second deadline is still
occupying the map at midnight. Count: bounded. Lifetime: unbounded. The MUST is half-met.

It also breaks the sibling document. `2026-09-01-continuation-telemetry.md` defines
`detected=reaped` as "nobody came back" and calls it *the abandonment rate `NFR.PERF.3` soaks for*.
If nothing calls `reap` outside pressure, that series is flat zero on every healthy gateway, and the
one counter an operator would use to see abandonment reports none of it. Two documents in this
increment depend on a reclaimer that the third had argued should not have a caller.

So: **two mechanisms, one for each clause of the MUST.**

| clause | mechanism | when it runs |
|---|---|---|
| bounded **count** | inline retain in `hold`, guarded by the earliest deadline | at capacity, in the caller about to be refused |
| bounded **lifetime** | `reap` called from `spawn_continuation_maintenance`, a lifecycle-owned interval task | every 60 s, independent of traffic |

The original objections to a reaper survive as *constraints on it*, not as reasons to omit it, and
they are met by spawning it the way `spawn_idle_reaper` is already spawned (`server/mod.rs:1962`).
`spawn_continuation_maintenance` takes the `ContinuationState` the router holds and ticks a
`tokio::time::interval` at 60 s, the same `SWEEP_INTERVAL` the idle reaper uses
(`server/mod.rs:1971`). Both serve modes start it beside the idle reaper: the HTTP path hands it a
subscription to the shutdown broadcast (`server/mod.rs:1364`), and `run_stdio`, which has no
broadcast channel, wraps it in an `AbortOnDrop` guard so every exit path aborts it
(`server/mod.rs:1546`). The tick is the one place that reads a clock — it passes `now` into `reap`,
keeping the module's rule that no reclamation path reads its own clock (`continuation.rs:518-521`) —
and it takes that clock as a constructor argument, so a test that advances the clock advances the
tick with it. The earliest-deadline guard makes a tick over a table with nothing expired an O(1)
comparison rather than a sweep. Sixty seconds is a bound on staleness, not on correctness: an
expired entry can hold its slot for up to one interval past its deadline, and a longer interval
delays a counter increment and holds a slot longer without wedging anything, because the inline
retain still owns the pressure case. Each removal increments `expired_total{detected="reaped"}`,
which is what gives that series a producer.

The **inline retain** is what `ConsumedLedger::consume` already does, and it is strictly better for
the *pressure* case: reclaim at the moment of pressure, in the caller that is about to be refused,
under a lock that caller was taking anyway. Cost is zero until the table is full; at capacity it is one
`retain` over 4 096 entries, on a path that was about to return an error. Nobody waits longer than
they would have.

So `InFlight::hold` gains the ledger's pattern, with one guard the ledger does not have:

> At capacity, retain over deadlines, then re-check. Refuse only if the table is still full.

### The scan needs a bound, because the caller that triggers it is unauthenticated

A bare inline retain is O(capacity) *per attempt*, and the attempts are attacker-controlled: once
the table is full, every subsequent `hold` — from any client, needing no privilege — scans 4 096
entries before refusing. That converts a cheap refusal into a lock-held sweep and hands an
unauthenticated caller a CPU amplifier on the path that routes everyone else's replies.

The bound is one `u64` beside the map: the **earliest deadline in the table**. At capacity, retain
only if that deadline has passed; otherwise refuse immediately, because a retain cannot free
anything. Recompute it during the retain that is already walking every entry, so it costs nothing
extra. Repeated pressure against an unexpired table is then O(1) per attempt, and the sweep happens
at most once per expiry rather than once per request.

This is a deliberate divergence from "copy the ledger's shape", named because §P3 says a decision
the design did not make is a design event. `ConsumedLedger` has the same amplification over a table
16× larger (65 536 entries, `:527-533`) and shipped without the guard. That is an **observation
recorded here, not a ticket**: the ledger's population is redeemed envelopes rather than open
rounds, so the two tables saturate under different traffic, and widening this change to fix a
shipped path is the scope drift §P0a exists to refuse. The guard goes where the new code goes.
### It is not "and nothing else" — the signature changes, and that is a design decision

A retain over deadlines needs a current time, and `hold` does not have one today:

```rust
pub async fn hold(&self, backend_id: &str, expires_at: u64) -> Option<String>
```

`expires_at` is the *new* entry's deadline and says nothing about whether the *existing* entries
have passed theirs. So `hold` gains a `now: u64` parameter, matching the idiom both neighbours
already use — `consume(&self, jti, expires_at, now)` at `:522` and `reap(&self, now)` at `:666`.
The tree injects clocks rather than reading them, which is also what makes the soak below able to
advance time instead of sleeping.

Named here rather than discovered during implementation, because it is a public-API change:
`InFlight::hold` is `pub`, and the **thirteen** existing call sites — all in `tests/mik_7212_acs.rs`, and `rg '\.hold\(' --glob '*.rs'`
returns no others — all update in the same commit. The compiler defines that inventory, not this
list; an earlier revision of this paragraph said eight, counted by hand, and was wrong. It is acceptable
because every one of them is in this repository and the alternative — reading a clock inside
`hold` — would make the soak untestable without sleeping, which is the property the neighbours were
designed to avoid.

Consequence worth stating plainly, and it is the opposite of what an earlier revision of this
paragraph said: **`reap` is required, and it needs a caller.** It is not a backstop the inline
retain makes optional — it is the mechanism for the `lifetime` half of `MRTR.8` and the sole
producer of `expired_total{detected="reaped"}`. What the inline retain removes is `reap`'s
responsibility for *availability*: a missed tick can no longer wedge the table, because pressure
reclaims on its own path. Staleness, not correctness, is what the interval trades.

### The earliest-deadline value lives under the same lock as the map

Stated because a cache beside a map is a correctness hazard in exactly two directions, and both are
silent. **Stale-high** (the cached deadline is later than the true earliest) suppresses a retain that
would have freed space — the table refuses with reclaimable entries in it, which is the wedge this
document exists to remove. **Stale-low** re-admits the amplification: every attempt passes the guard
and scans.

So it is a field of the same guarded structure, written under the same acquisition as the map it
describes, never an independent `AtomicU64`:

| operation | effect on the cached earliest deadline |
|---|---|
| `hold` admits | `min(cached, new entry's deadline)` — O(1) |
| `complete` removes | left unchanged. Removing an entry can only make the true earliest *later*, so the cache stays valid-low: a spurious retain that frees nothing, never a suppressed one |
| retain / `reap` sweeps | recomputed from the surviving entries during the same pass — the scan is already paying for the traversal |
| table empties | `u64::MAX`, so the guard refuses to scan an empty map |

The invariant is one line and it is deliberately one-sided: **the cached value is never later than
the true earliest deadline.** Valid-low costs a wasted scan; valid-high costs a wedge. The table
above never permits the second.

### Why not simply call `reap` from `hold`

`reap` takes `now` and locks the map; `hold` already holds that lock. Calling one from the other
either deadlocks or forces a lock-release-reacquire that opens a window where two callers both see
space. The retain goes inline, in the lock `hold` is already holding — exactly as `consume` does at
`:532`.

## The soak, and what it is allowed to observe

`NFR.PERF.3` asks for a soak, so the design has to say what it runs and what would make it fail —
otherwise the criterion is met by any test that does not crash.

| | |
|---|---|
| **drive** | epochs. Each epoch: fill the table to capacity with exchanges sharing a deadline `d`, abandon every one of them — never `complete`, never retry — then advance the injected clock past `d` and start the next epoch |
| **N** | several epochs, so the table is filled and drained repeatedly rather than once |
| **clock** | injected, not wall-clock — `hold` and the retain both take an explicit `now` (see the signature change above), so the soak *advances* time and never sleeps |
| **observes** | whether `hold` succeeds, and `InFlight::len()` after each cycle |
| **passes** | every `hold` succeeds; `len()` never exceeds capacity; and the first `hold` of each epoch after the first is served by reclamation, not by spare room |
| **fails** | the first `hold` that returns `None`. On today's code that is cycle 4 097, in the first epoch |

**Admission is the signal; occupancy is not.** The retain fires *at* capacity, so a correct
implementation reaches 4 096 entries and oscillates there — a pass condition demanding occupancy
stay *below* capacity would fail the very fix it is testing. What distinguishes reclaiming from
wedged is that `hold` keeps succeeding at the ceiling.

The epochs are what make that assertion honest rather than timing-dependent. A soak that trickled
entries with staggered deadlines could pass because some entry happened to expire just before each
admission — reclamation proved by luck. Filling an epoch, then stepping the clock past its single
shared deadline, means the admission at the start of the next epoch *can only* succeed if the retain
ran. Deterministic, and it names which line of the fix it is testing.

### Three cases the uniform-deadline epochs cannot reach

The epoch shape proves the *pressure* clause and is blind to the other two things this design now
claims.

**A lifetime case, because the epochs never idle.** Hold a handful of exchanges, abandon them,
advance the clock past their deadlines, and run *no further traffic at all*. The case constructs
`spawn_continuation_maintenance` over the table, hands it the clock it advances, and asserts through
that task: its body contains no call to `reap`. That is what separates it from
`tests/mik_7212_acs.rs:461`, which calls `reap` from the test and therefore proves the function
works rather than that anything in production runs it. Passes when the entries are gone and
`expired_total{detected="reaped"}` has advanced by exactly that many, with the tick as the only
thing that removed them. Fails if the map still holds them — which is what the pre-repair design would do, and is the `MRTR.8` `lifetime`
clause stated as an assertion instead of a paragraph. It is the only case in the plan that can fail
for the reason this revision exists.

**A staggered-deadline case, because uniform deadlines make the cache trivially correct.** With
every entry sharing one deadline, a cached earliest is right by construction and the invariant is
untested. Hold entries with deadlines spread across a range, expire them out of insertion order, and
interleave `complete` on live entries between admissions — each `complete` frees a slot, so the
case refills to capacity before the next admission and every assertion is made against a full table.
Passes when a `hold` is admitted at capacity exactly when at least one entry has genuinely expired,
and is refused otherwise. Stale-high is what this catches: a cached deadline later than the true
earliest suppresses the retain and the table refuses with reclaimable entries in it. Stale-low is
invisible to it by construction — the invariant permits stale-low, and it costs a scan that frees
nothing followed by the same refusal, so no admission decision changes.

**An idle-at-capacity case, because stale-low is invisible to every admission assertion.** Fill the
table to capacity with nothing expired and attempt a `hold`. Passes when the attempt is refused
*and* the retain did not run, counted rather than timed: the case holds a counter incremented on
entry to the retain and asserts it is still zero. That counter is test observability — no
reclamation path reads it — so it is not the independent `AtomicU64` the earliest-deadline cache is
forbidden to be. Without this case the amplifier guard has no observation that fails when every
refused attempt still walks the map.

Between them the staggered and idle-at-capacity cases read both directions of the invariant table
above; without them that table is prose.

The last row is what makes this a real test rather than a ritual: **it fails on the current tree**,
at a predictable point, for the stated reason. Written before the fix, it is the §P2 failing test;
the fix is done when it goes green.

Note what the soak deliberately does *not* measure: RSS. Process memory is the wrong instrument for
a fixed-capacity table — it would be flat both before and after the fix, and a green RSS graph is
exactly how this defect stays hidden. The instrument is occupancy and admission.

## Scope of the claim — the stateless population is out of it

`NFR.PERF.3` says "abandoned continuations", and only some continuations are things the gateway
holds. A stateless continuation is an envelope the gateway keeps no entry for; abandoning one
consumes nothing and reclaims nothing, and there is no table it could grow. It is therefore out of
scope here **by construction rather than by omission** — the population that cannot be observed is
the same population that cannot leak. `docs/design/2026-09-01-continuation-telemetry.md` states the
matching bound on `detected=reaped`, and the two documents must keep agreeing: the soak measures
the stateful population, and so does the counter.

## Trust boundary and threats

**C15.** `auth-user` at the front door, `unauth` for the property that matters here. Minting a
continuation binds a `principal_fingerprint` (`continuation.rs:75`, checked at `:175`), so a caller
is not anonymous to the envelope machinery. But `InFlight::hold` does not consult it: nothing in the
capacity path is keyed by principal, so *any* caller that can reach the legacy elicitation path can
occupy slots, and slots are shared across every principal. The authenticated identity is recorded
and not enforced against this resource — which is what makes this a security-adjacent availability
property rather than a performance tuning matter. Per-principal quotas would change that and are out
of scope; the honest statement is that this table has one shared pool. Data locality: `local`, one process's table. Partition behaviour: `AP` — a refusal
at capacity is a degraded answer, never an incorrect one.

**C6.** One threat dominates and the others are genuinely empty here.

| | threat | mitigation |
|---|---|---|
| **D** | a client starts elicitations and abandons them until the table wedges, denying the legacy path to every other client of that process | the inline retain: an abandoned entry stops occupying a slot the moment anyone else needs one. Capacity remains the bound; reclamation makes it a *live* bound instead of a lifetime total |
| **D** | the same client keeps pushing once the table is full, turning each refusal into a full-table scan under the lock | the earliest-deadline guard: at capacity with nothing expired, the refusal is O(1) and the sweep runs at most once per expiry. The mitigation for the first row must not become the mechanism for this one |
| **S/T/R/I/E** | — | no identity, no attacker-controlled content, and no authorisation decision reads this table; keys are gateway-minted (`:624`) and no caller may name another's |

The **D** row is the criterion restated as a threat, which is the honest reading of it:
`NFR.PERF.3` is a denial-of-service control wearing a performance number.

## Unknowns

| unknown | state |
|---|---|
| Is `ContinuationState` on the production path at all, or tests-only? | **Resolved: production.** `rg 'continuation:' src/ --glob '!*tests*'` gives `meta_mcp/mod.rs:401` (construction) and `server/mod.rs:1175` (handed to the router). Changed the design: the document is about a missing reclaimer, not about wiring a dead type. |
| Does either reclaimer run outside tests? | **Resolved: no.** `rg 'reap\(|evict_expired\('` matches only `tests/`. Changed the design: the ledger turned out not to need one and `InFlight` needs two — an inline retain in `hold` for the count clause, and a lifecycle-owned interval task calling `reap` for the lifetime clause. |
| Does anything in production call `InFlight::hold`? | **Resolved: no.** `rg '\.in_flight|\.hold\(|\.route\('` outside tests returns only the accessor's definition. Changed the design: the defect is stated as latent, and `NFR.PERF.3` closure now requires wiring evidence alongside the soak rather than the soak alone. |
| Does the at-capacity scan give an unauthenticated caller an amplifier? | **Resolved: yes, without a guard.** A bare retain is O(4 096) per refused attempt and the attempts need no privilege. Changed the design: the fix carries an earliest-deadline check the ledger does not have, and that guard is the first of the two divergences that stop the two tables sharing one rule. |
| Does `hold` already have a clock to retain against? | **Resolved: no.** `hold(&self, backend_id: &str, expires_at: u64)` (`:619`) carries only the new entry's deadline. Changed the design: the fix is a signature change, named above with its thirteen call sites, rather than a body-only edit. |
| Does the ledger have the same defect? | **Resolved: no.** `consume` (`:527-533`) retains before refusing. Changed the design: `hold` copies the ledger's retain-before-refusing shape for the count clause, and diverges from it for the rest — the ledger has no lifetime clause to bound and no unauthenticated amplifier to guard, so `InFlight` alone carries the periodic tick and the earliest-deadline check. |

## Out of scope

Any change to the capacities themselves. `CONSUMED_LEDGER_CAPACITY` and `IN_FLIGHT_CAPACITY` are
deployment decisions about availability (`continuation.rs:715-729` argues both), and this document
changes when a slot is freed, never how many there are. Making them configurable is a separate
question nobody has asked.
