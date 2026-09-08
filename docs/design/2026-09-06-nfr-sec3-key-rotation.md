# NFR.SEC.3 — rotatable continuation keys, retained for the max lifetime

Status: design, assertion-first tests and final code gates are approved by both
vendors. Implementation, focused regressions, coverage, mutation and component
measurements pass; the independent acceptance-only drive and parent-owned release
chain remain open. Final receipts and evidence are recorded at the end of the test plan.
Historical author: `sec-nfr`, 2026-09-06.
Round-by-round verdicts live in the table below, not in this line — a status line carrying round
state is stale the moment a leg returns, and it was, twice.

| round | leg | verdict | material_sha256 | material_bytes | ledger ts |
|---|---|---|---|---|---|
| 1 | glm-5.3 (substituting for kimi) | DO-NOT-SHIP | `3eff9bec…` — **unattested** | 205 | 08:04:40Z |
| 1 | grok | SHIP-WITH-FIXES | `3eff9bec…` — **unattested** | 205 | 08:10:02Z |
| 2 | glm-5.3 | SHIP-WITH-FIXES | `e56ef494…` | 15824 | 08:15:06Z |
| 2 | grok | SHIP-WITH-FIXES | `7462c16f…` | 15822 | 08:25:19Z |
| 3 | glm-5.3 | SHIP-WITH-FIXES | `a0888c5a…` | 26954 | 08:52:20Z |
| 3 | grok | SHIP-WITH-FIXES | `a0888c5a…` | 26954 | 08:56:18Z |
| 3c | grok — closure re-check | **SHIP** | `0ea50eb2…` | 56223 | 09:13:55Z |
| 3d | glm-5.3 — closure re-check | SHIP-WITH-FIXES | `a16ca238…` | 64007 | 09:24:45Z |

Rows 3c and 3d are closure re-checks, and there are TWO of them because both legs raised
findings in round 3 and the repair protocol sends closure back to the FINDER. Not to a fresh
vendor: a vendor that never raised a finding judges its materiality on its own line and
re-opens what it never asked about, which is a round generator inside the closure rule. One
consequence, easy to miss and missed here for one commit: closure is PER LEG. A single SHIP
closes the findings of the vendor that gave it and says nothing about the other leg's.

Row 3c is grok's, narrow mandate, repair commits only, and it returned SHIP: grok's F1
(interval, clock origin, successor rule), F2 (Q1 DEFERRED with its four fields) and F3 (the
C6 STRIDE table) are CLOSED. Three residuals came back with it, all verified at source
before repair: the STRIDE spoofing row named the wrong error variant, the startup key had no
clock to be stamped from, and the no-successor fallback was justified by an operator reload
that round 2 deleted.

Row 3d is the GLM leg's, on ITS four round-3 findings, which are different findings under
the same numbers: the per-mint counter writing under a read lock, the missing C6 STRIDE
table, Q1 labelled with a third state the design's own rule forbids, and the round-1 rows
presenting an unattested digest as a verdict. All four were repaired in `0532d2f0`, whose
subject names them; the closure row is what records that a reviewer, not the author, agrees
they are closed. It returned SHIP-WITH-FIXES: all four closed in substance, one LOW
finding, and that finding was THIS PARAGRAPH in its previous form — the closure narrative
named grok's three items as though they were the round's findings and dropped the
concurrency one, the finding that forced the `AtomicU64`, out of the record of its own
closure. Two improvements came with it, both adopted below: the `NotAuthentic` sources the
rotation log line correlates with, and the increment discipline for the counter.

The 3d digest closes the way row 3's does: 63,910 bytes submitted + 96 bytes of scope
string + one NUL = 64,007, the `material_bytes` in the row. Both were recomputed from the
submitted files rather than assumed; row 3's is worked through below. An arithmetic that
does not close means the row is not the review you think you are reading, and the rows above
these two have not had theirs recomputed — stated so that nobody reads this paragraph as
covering the whole table.

Text POST-DATING row 3d, which no reviewer has read — given by CATEGORY and deliberately
not by count, because a number in the one paragraph whose job is to be the auditable record
of what is unattested is a number a reader can falsify by recounting: the closure narrative
above, including the repair of the LOW finding GLM itself raised; the design passages
adopted from that row (both improvements, the sentence in the exhaustion section naming the
increment discipline, the age-check paragraph reverted alongside it, and the STRIDE
repudiation row); and this paragraph. GLM asked for both improvements, so the ASKS are
attested even though the answers are not. That gap is not theoretical: the first draft of the increment-discipline paragraph contradicted a decision
made two sections below it, and a re-read caught it rather than a review.

Keyed on `material_sha256` rather than on the ledger's `head`: `head` pins the branch tip at run
time and this branch is shared, so every row above carries a `head` belonging to some other
session's commit.

The digest is a weaker key than its name suggests, and both rounds show a different face of it.
Both wrappers compute `sha256(scope-arguments + NUL + staged-file)` — `digest()` at
`~/.claude/bin/synthetic-review:557`, `digest_material()` at `~/.claude/bin/grok-review:653`,
byte-identical in behaviour. Two consequences, each verified against the ledger rows rather than
reasoned:

- **Round 1's matching digest attests nothing about the material, and the material may never
  have reached the reviewers.** Both rows record `material_bytes` = 205 — the scope string
  alone, with no staged file behind it. The payload was handed over as a PATH inside the scope
  argument (`--scope … /private/tmp/…/kimi-design.txt`) with nothing on stdin, so the wrapper
  staged nothing and the digest covers 205 bytes of argument text. Piped material would have
  been staged and covered; a path in an argument is not. Identical digests there mean identical
  ARGV, and each reviewer saw the design only if it could open that path for itself — which the
  isolated leg cannot.
- **Round 2's differing digests do not mean differing material.** The rows are 15824 and 15822
  bytes against scope strings that differ by one character — `§P1 gate` versus `P1 gate`, and
  `§` is two bytes in UTF-8. The material was the same file; the scope was retyped. Reconciled,
  not open.

So the round-2 legs did review the same bytes, and round 1 is weaker than a DO-NOT-SHIP and a
SHIP-WITH-FIXES on one design make it look: its verdicts may rest on a scope line and a path. Recorded because the fix is mechanical and belongs to the wrappers,
not here: a digest whose name says `material` and whose input can omit the material is a claim
the review process makes and cannot support.

Round 3 is the first row whose digest attests what it claims to. The payload was PIPED rather
than named by a path, so the wrapper staged it and hashed it: 26,954 bytes = the 26,874-byte
material plus the 79-byte scope argument plus the NUL between them, arithmetic that closes
exactly. Round 1's 205 is the argument text with nothing staged behind it. Both legs were given a
byte-identical scope string this time, and BOTH ROUND-3 DIGESTS ARE `a0888c5a…` OVER 26,954
BYTES. That equality is the proof the field was always supposed to carry and never did: the two
vendors reviewed the same material, and neither verdict can be explained by one of them having
been shown something different. Round 1's shared `3eff9bec…` proves nothing of the kind — it is
the digest of a scope argument, equal because the argument was equal.

One provenance note for anyone re-checking the table: the GLM leg's row is written to
`~/.claude/data/kimi-review-ledger.jsonl`, not to `glm-review-ledger.jsonl`. The synthetic
wrapper names its ledger after the wrapper, not after the model it drove, so a scope-filtered
query against the file the model's name suggests returns NOTHING for a row that exists. Query
by digest, not by filename.

kimi is not in the table because it produced no row at all: `synthetic-review`'s trusted preamble
tells the model it may inspect the repository read-only, kimi has no filesystem, and it answered
with a hallucinated tool call three times running. Per §PA that is `MISSING`, never a scraped
verdict. Its earlier SHIP attests a payload from before `dd0acff5` — stale coverage, not a passed
leg. glm-5.3 stands in.

Round 2 deleted the rotation trigger outright and the text has moved again since, so a §P4
confirmation pass against the current revision is owed before this design is called reviewed.

## Delivery takeover clarification — current contract

The release lead resolved Q1 to existing option C, per-process mint-side age
rotation, under the approved single-process topology. No operator approval or
shared-key infrastructure is needed; restart is still not key rotation.
The paired current design/test-plan review must precede new tests and code.

Two arithmetic/atomicity repairs from direct inspection are part of that review.
At exact retirement+lifetime equality a verification key remains valid, so an
actively rotating production ring can contain **seven**, not six, keys at the
boundary (six retired/current-age cohorts plus the new minting key). Bound it by
`floor(CONTINUATION_LIFETIME_SECS / CONTINUATION_ROTATION_SECS) + 2`; do not prune
at equality to make the old count true. The 256-slot wrap-distance still holds.
A quota counter must never wrap after refusals: reserve one slot with a bounded
atomic `fetch_update`/CAS (Relaxed), stop incrementing at the per-key budget, and
reject without rotation until the age interval is reached. No load/check/separate-add race or unbounded increment is permitted.

The public raw-key constructor can preload verification keys with no retirement
epoch. Stamp the initial minting key and preload verification retirement epochs
at the first trusted mint; preserve verification before that mint. Production
uses one RNG-created key, so the seven-key bound is the production schedule bound;
a library caller's explicitly preloaded ring has its constructor-supplied bound
until its first retention window elapses. Never overwrite a still-retained
successor. First stamp and due-age recheck happen under the same write lock;
ordinary minting and verification use the read lock. Backward supplied time
neither rotates nor prunes; checked/saturating arithmetic must not wrap.

The test plan is `2026-09-06-nfr-sec3-key-rotation-test-plan.md`. It separately
proves age rotation, retirement-boundary retention, old-key pruning, concurrent
budget/rotation behavior and preservation of the actual continuation state.
No review of documentation alone closes NFR.SEC.3.

### Production clock and integration seam

Add a crate-private `ContinuationState::with_clock(Arc<dyn Fn() -> u64 + Send + Sync>)`
and `now()` accessor. Ordinary constructors bind `now_unix_secs`; the real
Gateway builder accepts the same trusted callback already specified by Change C's
CleanupRuntime, so worker and invoke share one epoch source. Replace the three
trusted reads in invoke's mint/retry validation paths with `continuation.now()`.
There is no wire parameter, public runtime switch or constructor wall-clock stamp.
Raw `Keyring::mint` still takes time solely from Payload::issued_at.

ROTATE.12 lives in an in-crate meta-MCP integration test module with access to the
same builder/runtime seam. Through the actual handle_tools_call path, initialize
a capable verified synthetic caller, receive a backend InputRequired/opaque
continuation at T, leave it pending, advance callback to T+60, mint a second
exchange through that path to trigger rotation, then answer/redeem the first
handle. Count actual backend dispatches and verify a duplicate redemption with
fresh explicit idempotency key cannot repeat the completed effect. Do not replace
the keyring, held table or consumed ledger, call raw mint to simulate this wiring,
or sleep 60 seconds. The backend and reply fixtures follow BRIDGE's actual
transport contract; tests own their temporary state and clock.

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
key age is `>= CONTINUATION_ROTATION_SECS`, retire it and mint a fresh one before proceeding; drop
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
limit both constrain the material that SEALS envelopes, and a process that has stopped minting
has no reason to mint a key. They are not two triggers: only the age limit rotates, and the
budget decides a refusal — see the counter discipline below.

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

`Keyring` holds one `parking_lot::RwLock<RingState>` containing the minting
kid and all verification entries. Use the existing dependency: its task-fair
policy avoids writer starvation; do not recursively acquire read guards. See
[parking_lot RwLock documentation](https://docs.rs/parking_lot/0.12.5/parking_lot/type.RwLock.html).
Ordinary mint and `open` take read guards; first stamping and age-due rotation
recheck and publish under the write guard. Seal/open remain inside their guard.
No Tokio lock or async public keyring API is introduced.

Every key owns an AtomicU64 quota counter. Reserve exactly one slot with bounded
`fetch_update`/CAS using Relaxed ordering; reject when already at budget without
incrementing. Failed reservations cannot wrap or reset the counter. The write
lock publishes each new key with counter zero; quota exhaustion never rotates.

The lock does not poison, so state publication must be transactional on panic as
well as on RNG errors. Retained key material/counters live in immutable shared
key objects; ring-entry creation/retirement metadata are copied into a candidate
RingState, not mutated in the live entries. Under the writer, prebuild and
validate the ENTIRE successor state, including retention filtering, unique kids,
initial stamps and new RNG key. Only then replace RingState with one non-panicking
assignment. No fallible call, test callback, logging, allocation or custom
panicking destructor may occur between field updates: there are no sequential
live field updates. A failpoint before replacement leaves the old snapshot,
quota and cryptographic behavior unchanged. After replacement the new state is
coherent; diagnostics happen after publishing. Keep `minting_kid` and entries
inside this one state, never separately updated locks.

One consequence of the lock that the current shape hides: `Keyring::key` returns
`Result<&LessSafeKey, _>` (`continuation.rs:524-530`), a borrow into `self.keys`. A borrow
cannot outlive the guard it came from, so the seal and the open happen INSIDE the guarded
scope rather than the key being handed back out of it. The alternative — cloning key material
out of the lock — puts a second copy of a secret on the stack for no reason, and widening
`mint`/`open` to `async` to use an async lock is the change this design already refused.

The lock must cover `minting_kid` AND `keys` AS ONE UNIT. They are separate fields today
(`:296-302`) and a rotation that swaps the vector without atomically swapping the minting kid
can mint under a kid that is not in the ring, or keep minting under the kid it just retired.
Two locks, or a lock around only the vector, reintroduces exactly the race the rotation is
supposed to be too simple to have.

Second point, easy to miss: `Keyring` also carries a minted counter and a mint budget
(`:297-301`). **Decided: `minted` resets to 0 on the new key.** The NIST bound the budget
encodes is per-key, so carrying the counter forward is simply wrong arithmetic — and it strands
a long-lived replica that exhausted one key with no way to mint again short of a restart. The
budget can still exhaust before the key is old enough to rotate, and the decision there is
that `mint` FAILS until the age check rotates it — at most one interval of stalled minting for
a replica minting fast enough to burn a per-key NIST bound in under an interval. That stall
begins at the exact envelope the bound names, not somewhere near it, and the bounded atomic reservation
discipline above is the whole reason: the refusal is decided by a slot number no two mints
share. Rotating on
exhaustion instead would hand the mint rate back to the caller, which is the attacker-triggered
rotation this design removed. The
draft framed this as two equal traps, which was wrong: the "unbounded budget via repeated
rotation" half assumed an attacker-triggerable rotation, and after the revision above there is
no operator trigger at all. Rotation is age-driven, so the mint rate is bounded by the clock.

Third, and it is the piece round 3 caught missing: the interval and the key's clock origin
are part of this design, not the implementer's to invent — deleting the timer deleted the schedule, and a schedule left unnamed comes back as a
second clock. Both are named here.

**`CONTINUATION_ROTATION_SECS: u64 = 60`**, a sibling constant to `CONTINUATION_LIFETIME_SECS`
at `src/protocol/continuation.rs:128` and, like it, deliberately not configurable. Each key
carries a `created_at` stamped from THE `now` HANDED TO `mint` — the same value that becomes
`payload.issued_at` (`:161-168`, `:408`), never a wall-clock read inside `Keyring::new` and
never a fresh `SystemTime::now()`. That is the whole point of having deleted the timer: one
clock, injected, testable by passing a different instant. A key stamped from any other source
reintroduces the split this revision removed, and it would do so invisibly, because both
clocks agree until they do not.

The startup key is the one case with no `now` to be stamped from: `ContinuationState::new`
(`continuation.rs:823`) builds it from the RNG at process start, and keeping `Keyring::new`
clockless is the whole point. So its `created_at` is stamped by the FIRST MINT, from that
mint's `issued_at`, BEFORE the age check runs. The alternative is a missing stamp read as
zero, under which the first mint sees an infinitely old key and rotates a key that has never
sealed anything — a fresh replica burning a kid on its first request, for nothing. One
`Option` and one order of operations, not a mechanism.

The SUCCESSOR RULE is the other half of that schedule, and naming the interval without it
would leave the arithmetic below open to two readings: the new kid is always
`minting_kid.wrapping_add(1)`, NEVER the lowest free slot. One clause, and it is what makes
the reuse distance a function of the interval at all. A lowest-free-slot search over a
small retained ring hands a retired kid straight back on the very next rotation, so the distance
would collapse from the number below to roughly the retention window itself — the same
mechanism, no margin, and nothing in the prose to say which was meant.

With the successor fixed the arithmetic is checkable rather than asserted. At one rotation
per 60 seconds against a 300-second retention window the live ring holds
`floor(CONTINUATION_LIFETIME_SECS / CONTINUATION_ROTATION_SECS) + 2 = 7` kids
at retirement+lifetime equality. Prune only when `now > retirement + lifetime`. Kid space is 256 and the counter advances by exactly one per
rotation, so a kid comes round again 256 intervals — 15,360 seconds — after its previous use,
against a retention window of 300. Fifty-one times the margin, and the bound to keep is
simply `(256 - 1) * CONTINUATION_ROTATION_SECS > CONTINUATION_LIFETIME_SECS`:
reuse is 256 intervals after creation but only 255 after retirement. Choosing an interval
that violates it does not corrupt anything: the successor kid is still live when its turn
comes round, so the fallback below fires every time and rotation silently stops. That is the
failure worth a test.

The age check is evaluated TWICE: once under the read guard to decide a rotation is due, and
again under the write guard before performing it. Two mints arriving either side of the
interval boundary would otherwise both see a due rotation and mint two new keys, burning kid
space at twice the designed rate. The second check costs one comparison on the rare path, and
it is what makes "exactly one rotation per racing set" true rather than hoped for. It is the
only trigger that needs the treatment, because it is the only trigger.

Fourth: `kid` is a `u8`, so the wrapping counter above returns to a value after 256
rotations. Decided rather than left open, because the successor rule and the interval
together make that distance knowable — a kid comes back only long after its previous holder
was dropped, and a dropped key's envelopes can no longer open. A rotation whose successor
kid is somehow still live does NOT fail its caller: it logs and keeps the current minting
key. The caller is `mint` — reload was dropped as a trigger in round 2, so justifying the
fallback by an operator's reload would be justifying it by a caller that no longer exists.
Rotation is a hygiene operation riding on a mint, and failing that mint — refusing a
continuation handle a user is waiting on — because key hygiene could not run is a worse
outcome than skipping one rotation.

Rotation emits one log line — old kid, new kid, retained-key count. It named the trigger
until round 3 pointed out that every trigger had been deleted: the field's only honest value
would be the constant "age", so it is a field whose value is a lie by omission. Without it the
`NotAuthentic` failures that DO occur have no correlating event, and a key ceremony with no
trail is not auditable.

Which failures those are is worth stating, because "residual failures around a rotation
window" reads like an expectation and this design does not have one. Rotation retires no key
that can still be presented: an envelope lives 300s and a kid is not reused for
`256 * 60 = 15,360s`, so no live envelope can meet a rotated-away key. The `NotAuthentic`
answers an operator will actually see come from elsewhere — an envelope presented to a replica
that did not mint it, and an envelope presented after the minting process restarted, since the
startup key comes from the RNG and nothing survives the restart. Neither is caused by
rotation, and the log line's job is to let an operator rule rotation out in one look. The
directly observable invariant failures are successor collisions or an invalid
RingState before publication. Log/alert those with bounded kid/count metadata.
Never infer an invariant failure from `NotAuthentic`: ciphertext tampering can
cause it for a live kid, and the untrusted encrypted expiry is unavailable on
a failed authentication. No token body, secret or claimed expiry is logged.

These are the invariants the implementation must hold, written here so the concurrency work
has checkable properties rather than prose:

1. `minting_kid` is always a member of `keys`.
2. No envelope is ever ACCEPTED under a key past its retention window — ACCEPTED, not opened:
   `expires_at` is inside the sealed payload, so the envelope is necessarily decrypted first and
   then refused, and a wording that forbade opening would contradict the reason rotation lives in
   `mint` alone. This is a property of the refusal, not of the ring's shape, and it holds
   without pruning: `issued_at` is at most the
   retirement instant `R`, so `expires_at` is at most `R + CONTINUATION_LIFETIME_SECS`, and the
   expiry check at `continuation.rs:508` refuses every such envelope on its own. Stating the
   invariant over the ring instead — *every retained key is within the lifetime of its
   retirement* — is what invariant 5 makes false: a replica that stops minting never prunes, and
   the stale key then sits in the ring with nothing wrong happening. Pruning is memory hygiene
   with no invariant riding on it.
3. Kids are unique within the live ring — a CONSEQUENCE of the successor rule, not a check to
   write: `minting_kid.wrapping_add(1)` advances by one, and
   `(256 - 1) * CONTINUATION_ROTATION_SECS > CONTINUATION_LIFETIME_SECS` keeps the returning value
   outside the live window. A test asserting uniqueness is really asserting that bound.
4. `minted` is 0 immediately after a rotation, on every path that rotates — and there is one.
   It is an `AtomicU64` on the key, not a field of the locked ring, so this is a property of
   the new key's construction rather than of the write guard.
5. Only `mint` writes the ring. `open` takes the read lock and returns a refusal reason decided
   by the payload, never by which keys happen to still be retained.

### C6 security pre-analysis — STRIDE short-form

Trust domain: `unauth` at the boundary (a continuation handle arrives from whatever holds it);
the keyring itself never leaves the process. Crypto: AES-256-GCM, unchanged by this design —
symmetric only, so T1c is an auto-PASS and no key agreement or signature is introduced.
Rotation changes the LIFETIME of key material and nothing about the primitive.

| class | does rotation change it | mitigation |
|---|---|---|
| Spoofing | yes | a forged or replayed kid resolves to a key that is gone or never existed; `open` refuses `UnknownKey` at `:489` (from `key()`, `:524-530`) before any payload is read. A LIVE kid presented under the wrong key is the other case and answers `NotAuthentic` at `:501`, from the AEAD tag. Two variants, two causes — a spoofing test written from the wrong one asserts nothing, and the NFR.SEC.4 tests already pin `UnknownKey` |
| Tampering | no | AEAD over the payload with the kid in the AAD; a rewritten kid fails the tag, it does not select a different key quietly |
| Repudiation | yes, improved | the rotation log line (old kid, new kid, retained count) is what makes a key ceremony auditable; without it a cross-replica or post-restart `NotAuthentic` cluster has no correlating event, and the operator cannot tell it apart from a rotation gone wrong |
| Information disclosure | no | nothing new is written to the envelope; `expires_at` was already inside the sealed payload and stays there |
| Denial of service | yes | a rotation whose successor kid is still live keeps the current key rather than failing its caller; a per-key budget exhausted early stalls minting for at most one interval, bounded above |
| Elevation of privilege | no | the handle carries no authority beyond resuming its own continuation; rotation does not widen what a valid handle can do |

### DoR conformance at the §P1 gate

Recorded as a block because a gate that has to be reconstructed from prose is a gate nobody
checks.

- **G6, two alternatives with reasons for rejection** — (a) rewrite the criterion, (b) shared
  key material; both below, with why.
- **G8, risks** — kid wrap at 256; the mint budget stranding a long-lived replica; a rotation
  timer as a second clock against the injected `now`; an `open` that prunes answering a kid
  miss where the build owes `Expired`. Each is analysed above and each changed the design.
- **G9, devil's advocate** — the trigger analysis overturned itself: three successive triggers
  (file watcher, meta-tool, interval task) were each argued for and then dropped, the last one
  deleted rather than tightened. That record is the devil's-advocate artifact.
- **C14, protocol first** — no wire change. `VERSION` stays 1, the kid is already carried in
  the AAD, and no field is added, removed or reinterpreted. A design that needed a schema bump
  would need it here; this one does not.
- **T1c, PQC** — symmetric only (AES-256-GCM). Auto-PASS, stated rather than assumed.

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

This was a §P3 design event: an earlier ledger interpretation selected (b). The
takeover delivery lead now selects (c) against the unchanged requirement and approved
topology boundary, as recorded in Q1 below. No operator-supplied key requirement is
removed, because none appears in NFR.SEC.3; no shared-state guarantee is claimed.

## Out of scope

Operator-supplied key material; cross-replica envelope portability; session affinity; any
shared store. Each is a capability beyond the criterion's text, and adding one re-opens
MRTR.5.

## Scheduled unknowns

None is a caveat. Each is either RESOLVED with a recorded answer or DEFERRED with the four
fields, and nothing depending on an open one gets built first.

| # | question | fail-fast |
|---|---|---|
| 1 | Does the rotation criterion require operator-supplied material? | **RESOLVED by the delivery lead, 2026-09-06.** NFR.SEC.3 requires versioning, live rotation and retention for the maximum continuation lifetime; it does not prescribe external/shared keys. Implement option C with per-process keys, mint-side age rotation and retention. Preserve the production-constructor separation case in RELEASE-4.0.0-test-plan.md (MRTR.5). The operator delegated release delivery and approved the topology boundary; this is the lead's engineering ruling, not an invented operator answer. A future requirement for shared keys needs its shared replay store and separate review. |
| 2 | What is "the max lifetime" as a number, and is it bounded anywhere today? RETAINED is unimplementable without it. | RESOLVED, checkable. `rg CONTINUATION_LIFETIME_SECS src/` — `const CONTINUATION_LIFETIME_SECS: u64 = 300` at `src/protocol/continuation.rs:128`, not a parameter and deliberately not one. The retention window is therefore 300 seconds, a compile-time constant. It changed the design: the retention deadline needs no new config and no new plumbing. |
| 3 | Can the config-reload path actually REACH the live keyring? The whole ROTATABLE claim, and the D7 WIRED argument with it, rests on this. | RESOLVED, checkable. `rg -n "MetaMcp\|continuation\|ContinuationState" src/config_reload/` — zero hits; `ReloadContext` (`:1371-1388`) holds config path, live config, registry, failsafe, TTL and env, and no gateway handle. The meta-tool caller reaches it for free, the file watcher does not. It changed the design twice: first the "free trigger" claim turned out half true, and then review showed the reload trigger was the wrong choice altogether. Every trigger was eventually dropped: the watcher for its plumbing, then the meta-tool and the interval task in round 2, in favour of an age check on the `now` already injected into `mint`. Written up above rather than left as a table cell. |

The takeover delivery lead resolved Q1 above and reconciled the criterion-status row.
The earlier option-B assumption is superseded; the requirements and planned constructor
separation assertion stay intact. Option C is the current design direction, not a claim
that rotation is implemented or validated. The separate test plan, failing-test review,
production wiring, retention/concurrency falsifiers and final review remain required.

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

### Mechanical module-size repair before final code review

FOR: move the unchanged Keyring/SealingKey/KeyEntry/RingState implementation and
its private test hooks to `src/protocol/continuation/keyring.rs`, with a public
`continuation::Keyring` re-export. Keep every public method, wire constant,
payload, clock and state behavior unchanged. OUT: new API, visibility of key
material, runtime cleanup changes or revised acceptance. Root separately owns
moving unchanged inline lifetime tests out of this shared file.

The 1469-line combined module exceeds the canonical 800-line gate; extracting
both cohesive sections brings each file below the limit. Alternatives: leave
it together (fails the gate), or split payload/state now (unnecessary ownership
and behavior-context churn). Keyring is the cohesive boundary already reviewed.
No benchmark interpretation or concurrency contract changes. GitNexus reports
LOW/0 for the type but HIGH/11 upstream nodes for `Keyring.open` (seven direct
callers: route lookup, redemption, benchmark and four MRTR tests); the latter
and static public-path searches are the conservative impact evidence.

The private rotation test module moves under `keyring` so its existing direct
private-state observations remain private. Test names gain only `::keyring`;
the 18 assertions remain unchanged. Its support path stays relative to the
actual source file and explicit imports obtain sibling state types. Validation:
byte-identical extracted implementation body, external old-path integration
compilation, focused 18+2 behavior tests and existing continuation regressions.
This mechanical move uses the canonical trivial/mechanical review exception;
parent peer review precedes edits and the final dual code pass includes the
full final files. No compiler failure is behavioral RED.

### Code finder repair: failed mint must release its unpublished hold

GPT code leg r1 confirmed a lifecycle gap in `mint_continuation`:
`begin_exchange` inserts a hold before `keyring.mint`; an `Err` logs and returns
no envelope, leaving capacity occupied without a client-visible continuation.
Successor RNG failure is newly relevant to ordinary rotation, while TooLarge
already takes the same path. This is a caller rollback repair within NFR.SEC.3,
with no new public capability or changed successful continuation semantics.

FOR (ROTATE.16): on every returned mint error, remove exactly that payload's
hold before returning the existing generic refusal; retain other live holds,
consumed-ledger state and the usable old token; a subsequent normal mint works.
Use `in_flight.complete(&payload.hold_key, payload.issued_at).await` in the error
arm. The payload timestamp is already trusted and avoids an additional clock
read. Existing `complete` owns its table locking; no key-ring guard survives
`mint` returning. OUT: new wire errors, constructor/state replacement, cancellation
or panic RAII refactoring, runtime fault injection, or preflight-size optimization.

Alternatives: a new begin-and-seal/lease abstraction broadens state ownership and
async cleanup for a single missing rollback; pre-rejecting oversized state alone
does not repair RNG or quota failures. The narrow error-arm rollback covers every
returned error with the existing release primitive. Risks: completing the wrong
hold or pruning a live unrelated hold; the test retains and later redeems a
separate successful exchange to falsify both.

Test plan before behavior: two actual-builder cases (rotation successor RNG
failure, oversized backend state) establish one live pending exchange, advance
its trusted clock to T+60, drive the refused second backend interim result, and
require the full held map and consumed-ledger count to equal their prior values.
Each then clears only its fixture fault, successfully mints another envelope,
and redeems the original pending exchange once. Cache is off for guard-driving
fixtures. Add a narrowly scoped cfg(test)-only crate-visible successor-failure
switch on Keyring to drive its existing private factory hook through the real
builder; it exposes no runtime API or material. The backend fixture supplies
oversized opaque state only when that case selects it. Before rollback is
implemented, both cases must compile and fail on the extra held entry. Then
separate tests-as-tests review precedes implementation, followed by green, a
remove-rollback sabotage, focused mutation/coverage and finder code closure.
DoR applicability remains the accepted takeover's crypto/security/process scope;
no new dependencies, identity, external state, durable storage or protocol shape.
These results are pending, not inferred from the earlier ring tests.
