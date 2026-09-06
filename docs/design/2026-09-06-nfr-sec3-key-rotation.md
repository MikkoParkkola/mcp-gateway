# NFR.SEC.3 — rotatable continuation keys, retained for the max lifetime

Status: DESIGN, not reviewed yet. No code exists. Author: `sec-nfr`, 2026-09-06.

## MRTR.5 is the hardest constraint, and it decides the design

Per-process key material is not an accident of the current build. It is the stated
enforcement mechanism for MRTR.5, at `src/protocol/continuation.rs:776-788`, verified at
source for this design rather than quoted from a prior report:

> Key material is generated here, per process, and written nowhere. So an envelope sealed
> by one replica is `NotAuthentic` on every other one, the set of replicas that can spend
> it twice is empty, and the one replica that can spend it at all does so atomically under
> `ConsumedLedger`'s own mutex — no shared store, no session affinity, no consensus. A
> configured shared key without a shared ledger is exactly the deployment the requirement
> forbids.

`ConsumedLedger`'s own doc (`:548-553`) states the same property from the other side:
process-local, "leaving no second ledger for a partition or a stale read to disagree with."

The double-spend set is empty BY CONSTRUCTION. No mechanism can double-spend, because no
second replica can open the envelope at all. That is a structural impossibility, and it is
the strongest form this property can take.

**A shared key destroys it and a shared ledger does not restore it.** A shared ledger
replaces impossibility with DETECTION: the spend becomes authentic on every replica, and
correctness moves from a local mutex to an external store that must be both correct and
reachable. Per the repair protocol's own test — after the fix, can the finding still be
STATED? — "two components can disagree about whether an envelope is spent" remains
statable under a shared ledger and is undescribable today. A shared ledger is therefore a
PATCH, and elimination is the default on an architecture finding.

## What the criterion actually says

> continuation envelope versioned, key rotatable, verification keys retained for the max
> lifetime

Three clauses. VERSIONED is met (`const VERSION: u8 = 1`, `:36`, carried in the AAD).
ROTATABLE and RETAINED are ABSENT.

The criterion says nothing about keys being SHARED between replicas, and nothing about
them being operator-supplied. Both are readings laid over the text, not the text itself.

## The gap is a trigger, not a container

Already built:

- `Keyring` (`:296`) holds a vector of key pairs — already multi-key.
- `open` (`:473`) selects by `kid` and refuses with an unknown-key error once material is gone.
- Three tests hand-build multi-key rings (`tests/mik_7212_acs.rs:195-245`).

Missing in production: `ContinuationState::new` (`:823`) builds a one-key ring from one
fresh random key; its only construction site is `MetaMcp::new`
(`src/gateway/meta_mcp/mod.rs:438`), reached only from startup paths. Config reload never
rebuilds it. So: no rotate operation, no retention deadline, no retire-after-lifetime.

## Recommended: per-replica in-place rotation (option C)

On config reload, the replica generates a NEW random key with a new `kid`, makes it the
minting key, and RETAINS prior key pairs until max envelope lifetime has elapsed, then
drops them. Key material stays per-process and written nowhere.

Against the three clauses:

- ROTATABLE — met. Trigger is config reload, a real production caller, so no D7 WIRED
  violation. A `rotate` added today with no caller WOULD be one.
- RETAINED — met. Old kids stay verifiable for the max lifetime; `open` already selects
  by kid and already refuses once dropped.
- VERSIONED — unchanged.

Against MRTR.5: **untouched.** An envelope sealed by replica A is still `NotAuthentic` on
B, because B holds none of A's kids. The double-spend set stays empty by construction.

Consequences that fall out rather than being designed:

- `ConsumedLedger` stays PER-PROCESS. No shared ledger, no distributed race, no external
  store on the correctness path. The fourth piece is not deferred — it is not needed.
- In-flight continuity comes free. The envelope now opens across a rotation because the old
  kid is retained, so the authentication failure is gone; and because the keyring rotates
  IN PLACE rather than `ContinuationState` being reconstructed, the in-flight map and the
  ledger survive. That is what a rotate copying keys and the UUID could not do.

### The real mechanical work

`ContinuationState` lives behind an `Arc` (`src/gateway/meta_mcp/mod.rs:230`) and `open`
takes `&self`, so the key vector must become interior-mutable — a read-write lock, read on
every open, written once per rotation. That is a LOCAL lock change, not a distributed one,
and it is the whole of the concurrency work.

Second point, easy to miss: `Keyring` also carries a minting kid, a minted counter and a
mint budget (`:297-301`). Rotation must decide what happens to that budget. Carrying the
old counter forward makes rotation pointless as a budget reset; resetting it silently gives
an attacker who can trigger reloads an unbounded mint budget. Named here as a decision, not
assumed.

Third: `kid` is a `u8`. 256 kids before wrap. With retention bounded by max envelope
lifetime the live set is tiny, but wrap must refuse or reuse deliberately, not by overflow.

## Rejected alternatives

**(a) Rewrite the criterion so existing code satisfies it.** Refused before it was
considered. The standing ruling at `docs/requirements/RELEASE-4.0.0-blocking-rollup.md:18`
("narrowing a criterion is not available on this release") closes it; the recorded operator
agreement runs the other way, `:25-27` — "implement the full 4.0.0 scope, with all gaps
fixed with the full scope". Cited, not re-argued.

**(b) Config-supplied shared keys + reload-time rotation + shared consumed-ledger +
in-flight continuity.** Feasible, and strictly worse on the property named above as the
hardest constraint. It trades a structural impossibility for a detection mechanism whose
correctness depends on an external store's atomicity and reachability, and it must then
answer what a partition does — fail closed and lose liveness, or fail open and lose MRTR.5.
It is also the larger build by a wide margin. Rejected because (c) meets all three clauses
of the criterion as written WITHOUT paying that, not because it is too big.

This is a §P3 design event and is named as one: (b) is the scoped instruction, and this
design declines three of its four pieces. That decision belongs to the team lead to confirm
or overturn, not to be taken silently here.

## Out of scope

Operator-supplied key material; cross-replica envelope portability; session affinity; any
shared store. Each is a capability beyond the criterion's text, and adding one re-opens
MRTR.5.

## Scheduled unknowns

Neither is a caveat; both have a check that can come back "no", and nothing depending on
them gets built first.

| # | question | fail-fast |
|---|---|---|
| 1 | Does the criterion's author read "rotatable" as requiring operator-supplied material? If yes, (c) does not meet it and (b) returns. | ASKABLE, not checkable — asked of the team lead in the message accompanying this design. Blocks all four pieces. |
| 2 | What is "the max lifetime" as a number, and is it bounded anywhere today? RETAINED is unimplementable without it. | RESOLVED, checkable. `rg CONTINUATION_LIFETIME_SECS src/` — `const CONTINUATION_LIFETIME_SECS: u64 = 300` at `src/protocol/continuation.rs:128`, not a parameter and deliberately not one. The retention window is therefore 300 seconds, a compile-time constant. It changed the design: the retention deadline needs no new config and no new plumbing. |

Question 1 is load-bearing: a yes reverses the recommendation.

## The repo already ticketed option (b), and sequenced it after this release

Found while resolving question 2, in the doc on the lifetime constant itself
(`src/protocol/continuation.rs:120-128`):

> the spent-ledger that makes redemption single-use is a fixed-capacity table in this
> process, so a continuation that outlives its entry stops being single-use. Five minutes is
> a person answering a prompt, not a session.
>
> Keys do not outlive the process, and neither does the ledger. Persistent keys arrive with
> the durable ledger (MIK-7312) and not before.

That is option (b), already carrying a ticket number, already sequenced after this release,
and already stating the coupling this design argues for independently: persistent keys and a
durable ledger ship TOGETHER or MRTR.5 breaks. So (b) is not being refused here — it is being
left where the codebase already put it. What (c) adds is that SEC.3's three clauses need not
wait for MIK-7312, because none of them asks for a persistent key.
