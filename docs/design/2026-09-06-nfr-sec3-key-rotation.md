# NFR.SEC.3 — rotatable continuation keys, retained for the max lifetime

Status: DESIGN, dual-reviewed, no code exists. Author: `sec-nfr`, 2026-09-06.
Round-by-round verdicts live in the table below, not in this line — a status line carrying round
state is stale the moment a leg returns, and it was, twice.

| round | leg | verdict | material_sha256 | ledger ts |
|---|---|---|---|---|
| 1 | glm-5.3 (substituting for kimi) | DO-NOT-SHIP | `3eff9bec…` | 08:04:40Z |
| 1 | grok | SHIP-WITH-FIXES | `3eff9bec…` | 08:10:02Z |
| 2 | glm-5.3 | SHIP-WITH-FIXES | `e56ef494…` | 08:15:06Z |
| 2 | grok | SHIP-WITH-FIXES | `7462c16f…` | 08:25:19Z |

Keyed on `material_sha256` rather than on the ledger's `head`: `head` pins the branch tip at run
time and this branch is shared, so every row above carries a `head` belonging to some other
session's commit.

The digest is a weaker key than its name suggests, and both rounds show a different face of it.
Both wrappers compute `sha256(scope-arguments + NUL + staged-file)` — `digest()` at
`~/.claude/bin/synthetic-review:557`, `digest_material()` at `~/.claude/bin/grok-review:653`,
byte-identical in behaviour. Two consequences, each verified against the ledger rows rather than
reasoned:

- **Round 1's matching digest attests nothing about the material.** Both rows record
  `material_bytes` = 205, which is the scope string alone: the payload went in on STDIN, and
  stdin is outside what the digest covers. Identical digests there mean identical ARGV.
- **Round 2's differing digests do not mean differing material.** The rows are 15824 and 15822
  bytes against scope strings that differ by one character — `§P1 gate` versus `P1 gate`, and
  `§` is two bytes in UTF-8. The material was the same file; the scope was retyped. Reconciled,
  not open.

So the round-2 legs did review the same bytes, and the round-1 pair is unattested by anything
except my own invocation. Recorded because the fix is mechanical and belongs to the wrappers,
not here: a digest whose name says `material` and whose input can omit the material is a claim
the review process makes and cannot support.

kimi is not in the table because it produced no row at all: `synthetic-review`'s trusted preamble
tells the model it may inspect the repository read-only, kimi has no filesystem, and it answered
with a hallucinated tool call three times running. Per §PA that is `MISSING`, never a scraped
verdict. Its earlier SHIP attests a payload from before `dd0acff5` — stale coverage, not a passed
leg. glm-5.3 stands in.

Round 2 deleted the rotation trigger outright and the text has moved again since, so a §P4
confirmation pass against the current revision is owed before this design is called reviewed.

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

- ROTATABLE — met, and with no trigger to wire: rotation is an age check inside `mint`,
  which is the production path, so D7 WIRED holds by construction. A `rotate` added
  today with no caller WOULD be a violation; that is exactly why the three candidate triggers
  below were all dropped in favour of the lazy check.
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
caller". It no longer rests on a trigger at all — see the revision below, where the last of
them is dropped. What follows is the source check that started that unravelling, kept because
it is what moved the design.

Checked at source rather than assumed, because a wrong answer here does not weaken the design
— it moves the trigger somewhere else and rewrites this section.

Superseded by the revision below — both rows are dropped triggers now — but recorded because
the check is what moved the design: neither `ConfigWatcher::start` nor `ReloadContext`
holds any handle to `MetaMcp` or the continuation state, so the watcher leg was never the free
trigger the first draft claimed. The meta-tool leg does reach it, on `&self` of `MetaMcp`, which
owns `continuation: Arc<ContinuationState>`.

Third fact, and it is why the reload trigger is wrong: **there is no continuation or key section
in `Config` at all**, because the key is process-random and written nowhere. So no config
FIELD can change to signal a rotation, and `pending_restart_fields` (`src/config_reload/mod.rs:550`)
has nothing to say about it either.

### Revised twice under review: no trigger at all — rotation is lazy

Round 1 finding, accepted: reload is a POOR trigger and choosing it manufactured the whole
two-caller problem above. A replica that never reloads never rotates, so ROTATABLE would be met
as a capability and never in practice; and because no continuation setting exists, a
reload-driven rotation fires on an unrelated backend-URL edit — a behaviour nobody asked for.
That round replaced the watcher with an interval task.

Round 2 finding, from the other vendor, also accepted, and it deletes more than round 1 did:
**the interval task is a second clock this module does not need.** `Keyring::open` already takes
an injected `now: u64` (`src/protocol/continuation.rs:473`) and `Keyring::mint` has the same
instant in `payload.issued_at` (`:161-168`, `:408`). Rotation is an age check against a clock
already in hand at both call sites. A timer adds a second, independent clock, and a time split
between the two is exactly the `UnknownKey` failure that RETAINED exists to prevent.

So: **rotate lazily, inside `mint` alone, off the `now` already passed in.** If the minting
key is older than the rotation interval, retire it and mint a fresh one before proceeding; drop
retained keys whose retirement is more than `CONTINUATION_LIFETIME_SECS` behind `now` in the same
pass. Nothing is spawned, nothing is shut down, no constructor changes.

**`open` never mutates the ring — not the keys, not the minting kid.** The draft had both sides
rotating, which is one line shorter and wrong. `Keyring::open` resolves the kid at
`src/protocol/continuation.rs:489` and only reaches the expiry check at `:508`, because
`expires_at` lives inside the sealed payload and cannot be read before the key that decrypts it.
So an `open` that prunes can drop the key an envelope needs and answer `UnknownKey` where the
build is supposed to answer `Expired`. The arithmetic keeps that refusal *correct* — a key is only
prunable once every envelope under it is past its deadline — but it moves the REASON, and
`RELEASE-4.0.0-test-plan.md:302` is a coverage row for exactly that refusal: *a token past its
`expires_at` is refused on the replica that minted it, with the clock advanced*. A build with no
`expires_at` derivation at all would still refuse that token via the kid-miss, so the row would go
green on the defect it exists to catch. Pruning only in `mint` removes the interaction rather than
documenting it: `open` takes a read lock, resolves whatever the ring holds, and the reason it
returns is decided by the payload.

Rotation belonging to `mint` is also the plainer reading of the bound. The budget and the age
limit are about the material that SEALS envelopes; a process that has stopped minting has no
reason to mint a key.

| trigger | verdict | why |
|---|---|---|
| file watcher (`ConfigWatcher::start`) | **DROPPED** (round 1) | the only piece needing new plumbing, and it coupled rotation to file edits that say nothing about keys. |
| interval task | **DROPPED** (round 2) | a second clock. It also forced a spawn site, a shutdown subscription, and a `tokio::spawn`-outside-a-runtime hazard in eight synchronous `ContinuationState::new()` call sites. All three concerns vanish with the task. |
| `gateway_reload_config` meta-tool | **DROPPED** (round 2) | the same coupling argument that killed the watcher: rotating keys because an operator edited a backend URL is a side effect, not a verb. |
| age check inside `mint` | **THE MECHANISM** | zero plumbing, one clock, and it is on the production path by construction — which is also how D7 WIRED is satisfied, without a meta-tool nobody calls. `open` reads the ring and never rotates or prunes it; see above for why that is a correctness requirement and not a tidiness preference. |

This is the shape the module already uses elsewhere: `ContinuationState`'s own
`ConsumedLedger::evict_expired(now)` (`:619`) is a lazy evictor with no timer behind it, and the
response cache and the signing nonce store both call their own `evict_expired` inline from the
operation itself.

**No operator rotate verb in v1, and that is deliberate.** The criterion says the key is
*rotatable*; age-based rotation rotates it, unprompted, on every live replica. A manual verb
would cost either a new meta-tool — against this repo's locked decision to keep the Meta-MCP
surface compact — or the reload coupling just dropped. If the requester wants an explicit
operator lever, that is a decision for them and it is cheap to add later; it is not needed to
meet the criterion.

The interval is a compile-time constant beside `CONTINUATION_LIFETIME_SECS`
(`src/protocol/continuation.rs:128`), not new config — same reasoning that kept the retention
window out of config. `CONTINUATION_LIFETIME_SECS` stays the SINGLE source of the retention
deadline; the rotation code must not carry a second copy of the number.

### The real mechanical work

`ContinuationState` lives behind an `Arc` (`src/gateway/meta_mcp/mod.rs:230`) and `open`
takes `&self`, so the key vector must become interior-mutable — **`std::sync::RwLock`**, taken
for READ on every `open` and for WRITE only by the rotation inside `mint`. Explicitly NOT the `tokio::sync::Mutex` that
`ConsumedLedger` and `InFlight` use (`:561`, `:668`): those are `async fn`s already, `mint` and
`open` are not, and copying their lock type would make every call site of both `async`. That is a LOCAL lock change, not a distributed one,
and it is the whole of the concurrency work.

The lock must cover `minting_kid` AND `keys` AS ONE UNIT. They are separate fields today
(`:296-302`) and a rotation that swaps the vector without atomically swapping the minting kid
can mint under a kid that is not in the ring, or keep minting under the kid it just retired.
Two locks, or a lock around only the vector, reintroduces exactly the race the rotation is
supposed to be too simple to have.

Second point, easy to miss: `Keyring` also carries a minted counter and a mint budget
(`:297-301`). **Decided: `minted` resets to 0 on the new key.** The NIST bound the budget
encodes is per-key, so carrying the counter forward is simply wrong arithmetic — and it strands
a long-lived replica that exhausted one key with no way to mint again short of a restart. The
draft framed this as two equal traps, which was wrong: the "unbounded budget via repeated
rotation" half assumed an attacker-triggerable rotation, and after the revision above there is
no operator trigger at all. Rotation is age-driven, so the mint rate is bounded by the clock.

Third: `kid` is a `u8`. 256 kids before wrap. Decided rather than left open, because the
age-based rotation makes the rate knowable: at one rotation per interval the live ring holds
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
2. No envelope is ever OPENED under a key past its retention window. This is a property of the
   refusal, not of the ring's shape, and it holds without pruning: `issued_at` is at most the
   retirement instant `R`, so `expires_at` is at most `R + CONTINUATION_LIFETIME_SECS`, and the
   expiry check at `continuation.rs:508` refuses every such envelope on its own. Stating the
   invariant over the ring instead — *every retained key is within the lifetime of its
   retirement* — is what invariant 5 makes false: a replica that stops minting never prunes, and
   the stale key then sits in the ring with nothing wrong happening. Pruning is memory hygiene
   with no invariant riding on it.
3. Kids are unique within the live ring.
4. `minted` is 0 immediately after a rotation, on every path that rotates — and there is one.
5. Only `mint` writes the ring. `open` takes the read lock and returns a refusal reason decided
   by the payload, never by which keys happen to still be retained.

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
| 3 | Can the config-reload path actually REACH the live keyring? The whole ROTATABLE claim, and the D7 WIRED argument with it, rests on this. | RESOLVED, checkable. `rg -n "MetaMcp\|continuation\|ContinuationState" src/config_reload/` — zero hits; `ReloadContext` (`:1371-1388`) holds config path, live config, registry, failsafe, TTL and env, and no gateway handle. The meta-tool caller reaches it for free, the file watcher does not. It changed the design twice: first the "free trigger" claim turned out half true, and then review showed the reload trigger was the wrong choice altogether. Every trigger was eventually dropped: the watcher for its plumbing, then the meta-tool and the interval task in round 2, in favour of an age check on the `now` already injected into `mint`. Written up above rather than left as a table cell. |

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


**T1c (PQC readiness) — N/A, recorded rather than skipped.** This design adds no key-agreement
and no signature primitive. It rotates an existing symmetric AES key, which is the DoR T1c
symmetric-only fast path (`HMAC`/`AES`/`ChaCha` = auto-PASS).
