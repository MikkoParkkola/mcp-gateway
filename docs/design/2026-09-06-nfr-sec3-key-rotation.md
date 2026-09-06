# NFR.SEC.3 — rotatable continuation keys, retained for the max lifetime

Status: DESIGN, under dual review (glm-5.3 substitution leg returned SHIP-WITH-FIXES; second leg in flight). No code exists. Author: `sec-nfr`, 2026-09-06.

## MRTR.5 is the constraint that decides this design — and its text is narrower than the first draft claimed

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

### What MRTR.5 actually says, and the claim this design first got wrong

Quoted rather than paraphrased, because the first draft of this section argued from the
enforcement comment instead of the criterion and overstated the result. The criterion is two
rows in `docs/requirements/RELEASE-4.0.0-criteria-status.md:132-133`:

> `MIK-7212.MRTR.5a` — a continuation MUST be single-use
> `MIK-7212.MRTR.5b` — a continuation MUST expire

Neither mentions replicas. **A linearizable shared ledger with atomic check-and-spend
PREVENTS a double spend while it is reachable — it does not merely detect one.** The earlier
"a shared ledger only detects" framing was wrong and is withdrawn. What survives is narrower
and is the real difference: today the property holds by construction with no reachable
dependency; under (b) it holds conditionally on an external store being both linearizable and
up, which forces the partition dichotomy — fail closed and lose liveness, or fail open and
lose 5a.

The binding objection to (b) is therefore not this prose at all. It is a test-plan row that
already exists: the §P2 coverage row for `MIK-7212.MRTR.5` at
`docs/requirements/RELEASE-4.0.0-test-plan.md:301`. Stated exactly — that plan's header still
reads `Status: DRAFT for review`, and its trailing `Yes` column is *Can it fail?*, not a
blocking marker. What gives the row its force is not a status label but what it asserts:

> A token minted by one `AppState` is refused by a second one built through the production
> constructor from the same configuration, the refusal is `NotAuthentic`, and it is decided
> before any ledger lookup […] Any implementation that derives key material from
> configuration or reads it from the environment gives both processes the same key, and
> fails here while passing every single-process row.

Option (b) is config-supplied key material. That row fails by construction under (b) — not on
a judgement call, on the row's own sentence. Meeting (b) therefore means DROPPING the planned
coverage of an acceptance criterion, and the repair protocol reserves that to the requester,
recorded, before it happens. The plan being formally draft lowers the ceremony, not the
substance: the row states a property of MRTR.5 that (b) cannot hold.

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

On a rotation trigger, the replica generates a NEW random key with a new `kid`, makes it the
minting key, and RETAINS prior key pairs until max envelope lifetime has elapsed, then
drops them. Key material stays per-process and written nowhere. Which triggers, and why the
first draft picked the wrong one, is settled two sections down.

Against the three clauses:

- ROTATABLE — met. Two triggers, both real production callers, so no D7 WIRED violation: the
  `gateway_reload_config` meta-tool is the operator-invocable verb, and an interval task
  guarantees the cadence when nobody invokes it. A `rotate` added today with no caller WOULD
  be a violation. Which triggers survive review, and which was dropped, is below.
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

### Where the trigger comes from — the one place this design could have been wrong

The ROTATABLE claim originally rested entirely on "config reload is a real production
caller". It no longer does — the interval task below carries the cadence, and reload survives
only as the operator's explicit rotate verb. What follows is the source check that decided
which of reload's two callers stays.

Checked at source rather than assumed, because a wrong answer here does not weaken the design
— it moves the trigger somewhere else and rewrites this section.

| caller | reaches `ContinuationState`? | cost |
|---|---|---|
| `gateway_reload_config` meta-tool (`src/gateway/meta_mcp/invoke.rs:2836`) | YES | zero. It runs on `&self` of `MetaMcp`, which already owns `continuation: Arc<ContinuationState>` (`src/gateway/meta_mcp/mod.rs:230`). One call after the reload returns. |
| file watcher (`ConfigWatcher::start`, called at `src/gateway/server/mod.rs:1276`) | NO | one new parameter. It takes `config_path`, `live_config`, `registry`, `initial_config`, `env`, `shutdown_rx` (`src/config_reload/mod.rs:1010-1017`) and forwards them to `spawn_reload_task`. Neither it nor `ReloadContext` (`:1371-1388`) holds any handle to `MetaMcp` or the continuation state. |

The watcher's plumbing is cheap but it is not free, and the design claimed free. It is a
parameter rather than a restructure because `meta_mcp` is built at `server/mod.rs:1011` and
the watcher starts at `:1276` in the same function, so the `Arc` is already in scope at the
call site.

Third fact, and it is why the reload trigger is wrong: **there is no continuation or key section
in `Config` at all**, because the key is process-random and written nowhere. So no config
FIELD can change to signal a rotation, and `pending_restart_fields` (`src/config_reload/mod.rs:550`)
has nothing to say about it either.

### Revised after review: the watcher leg is dropped and a timer is added

A reviewer's finding, accepted rather than argued: reload is a POOR trigger and choosing it
manufactured the whole two-caller problem above. A replica that never reloads never rotates,
so ROTATABLE would be met as a capability and never in practice; and because no continuation
setting exists, a reload-driven rotation fires on an unrelated backend-URL edit — a behaviour
nobody asked for.

The revision is strictly smaller than what it replaces:

| trigger | keep? | why |
|---|---|---|
| `gateway_reload_config` meta-tool (`src/gateway/meta_mcp/invoke.rs:2836`) | KEEP | free — runs on `&self` of `MetaMcp`, which already owns `continuation`. It is the operator-invocable lever, which is what makes ROTATABLE a verb rather than a property. |
| file watcher (`ConfigWatcher::start`) | **DROP** | this was the only piece needing new plumbing, and it was coupling rotation to file edits that say nothing about keys. Removing it deletes the new parameter, the `ReloadContext` question and the two-caller table. |
| interval task, spawned beside the server's other background tasks | **ADD** | guaranteed cadence: rotation no longer depends on an operator ever reloading. It also gives eager retention pruning a home, so the ring holds only keys inside the 300s window instead of only pruning at the next rotation. |

Two decisions the timer forces, named here rather than left to the implementer:

**Where it is spawned — NOT in `ContinuationState::new`.** `MetaMcp::build`
(`src/gateway/meta_mcp/mod.rs:427`) and `MetaMcp::new` (`:488`) are plain synchronous
functions, and `ContinuationState::new()` is called from `build` at `:438` and from seven
synchronous test constructors in `src/gateway/router/tests.rs`. `tokio::spawn` panics outside
a runtime, so a constructor that spawns turns every one of those into a panic. The task is
spawned at the server, exactly where `spawn_idle_reaper` already is
(`src/gateway/server/mod.rs:1393`, defined `:2124`), with the identical signature shape:
`(Arc<ContinuationState>, Option<broadcast::Receiver<()>>)`.

**How it stops.** From the same shutdown broadcast every other background task uses —
`shutdown_tx.subscribe()` at the call site, `select!`-ed against the interval tick, exactly as
`ConfigWatcher::start` (`src/gateway/server/mod.rs:1282`) and the cost sweeper (`:1400-1416`)
do. Without it the task holds its `Arc<ContinuationState>` alive past shutdown and never
stops. This is the one line of new plumbing the design has, and it is a line this file already
writes five times.

The interval is a compile-time constant beside `CONTINUATION_LIFETIME_SECS`
(`src/protocol/continuation.rs:128`), not new config — same reasoning that kept the retention
window out of config. `CONTINUATION_LIFETIME_SECS` stays the SINGLE source of the retention
deadline; the rotation code must not carry a second copy of the number.

### The real mechanical work

`ContinuationState` lives behind an `Arc` (`src/gateway/meta_mcp/mod.rs:230`) and `open`
takes `&self`, so the key vector must become interior-mutable — a read-write lock, read on
every open, written once per rotation. That is a LOCAL lock change, not a distributed one,
and it is the whole of the concurrency work.

The lock must cover `minting_kid` AND `keys` AS ONE UNIT. They are separate fields today
(`:296-302`) and a rotation that swaps the vector without atomically swapping the minting kid
can mint under a kid that is not in the ring, or keep minting under the kid it just retired.
Two locks, or a lock around only the vector, reintroduces exactly the race the rotation is
supposed to be too simple to have.

Second point, easy to miss: `Keyring` also carries a minted counter and a mint budget
(`:297-301`). Rotation must decide what happens to that budget. Carrying the old counter
forward makes rotation pointless as a budget reset; resetting it silently gives an attacker
who can trigger reloads an unbounded mint budget. Named here as a decision, not assumed.

Third: `kid` is a `u8`. 256 kids before wrap. Decided rather than left open, because the
timer trigger makes the rate knowable: at one rotation per interval the live ring holds
`ceil(300 / interval) + 1` kids, so a kid is REUSED only once its previous holder has been
dropped — safe by definition, since a dropped key's envelopes can no longer open. A rotation
that cannot find a free kid does NOT fail its caller: it logs and keeps the current minting
key. Rotation is a hygiene operation, and failing an operator's reload because key hygiene
could not run is a worse outcome than skipping one rotation.

Rotation emits one log line — old kid, new kid, trigger, retained-key count. Without it the
residual `NotAuthentic` failures around a rotation window have no correlating event, and a key
ceremony with no trail is not auditable.

These are the invariants the implementation must hold, written here so the concurrency work
has checkable properties rather than prose:

1. `minting_kid` is always a member of `keys`.
2. Every retained key is within `CONTINUATION_LIFETIME_SECS` of its retirement.
3. Kids are unique within the live ring.
4. The mint budget's treatment across a rotation is whatever the decision above settles, and
   it is the same on every path.

## Rejected alternatives

**(a) Rewrite the criterion so existing code satisfies it.** Refused before it was
considered. The standing ruling at `docs/requirements/RELEASE-4.0.0-blocking-rollup.md:18`
("narrowing a criterion is not available on this release") closes it; the recorded operator
agreement runs the other way, `:25-27` — "implement the full 4.0.0 scope, with all gaps
fixed with the full scope". Cited, not re-argued.

**(b) Config-supplied shared keys + reload-time rotation + shared consumed-ledger +
in-flight continuity.** Feasible, and it does meet MRTR.5's text — a linearizable shared
ledger prevents a second spend, it does not merely notice one. Two things stand against it,
and only the first is decisive. It fails the planned MRTR.5 coverage row as written
(`RELEASE-4.0.0-test-plan.md:301`, quoted above), so adopting it requires the requester to
rewrite that criterion, recorded, before the work starts. And it moves single-use from a
property that holds by construction to one conditional on an external store being
linearizable and reachable, which forces the partition answer — fail closed and lose
liveness, or fail open and lose 5a. It is also the larger build by a wide margin, which is
the least interesting objection and is not why it is declined here.

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
| 3 | Can the config-reload path actually REACH the live keyring? The whole ROTATABLE claim, and the D7 WIRED argument with it, rests on this. | RESOLVED, checkable. `rg -n "MetaMcp\|continuation\|ContinuationState" src/config_reload/` — zero hits; `ReloadContext` (`:1371-1388`) holds config path, live config, registry, failsafe, TTL and env, and no gateway handle. The meta-tool caller reaches it for free, the file watcher does not. It changed the design twice: first the "free trigger" claim turned out half true, and then review showed the reload trigger was the wrong choice altogether. The watcher leg is dropped, the meta-tool leg is kept as the operator's rotate verb, and an interval task supplies the cadence. Written up above rather than left as a table cell. |

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
