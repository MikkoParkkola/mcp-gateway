<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MIK-7417.SEC3 — continuation key rotation and retention: test plan

Status: plan, for review. Design: `2026-09-06-nfr-sec3-key-rotation.md`.
Criterion: *continuation envelope versioned, key rotatable, verification keys
retained for the max lifetime*. VERSIONED is already met (`const VERSION: u8 = 1`,
`src/protocol/continuation.rs:36`); this plan covers ROTATABLE and RETAINED.

Written per §P2: one row per acceptance criterion, its V-model level, its type, and
its evidence. **An empty evidence cell is the finding, not an omission** — every such
cell below names a test that does not exist yet, and the failing-tests step writes it.

## Acceptance criteria

Mined from the clause text and the design's invariant list (`:447-466`), per ruling
`R24`. Each is a property of the shipped mechanism, not of a fixture.

- `MIK-7417.SEC3.1` — Given a keyring whose minting key was created more than
  `CONTINUATION_ROTATION_SECS` before `now`, When `mint` is called with that `now`,
  Then the ring rotates before sealing and the envelope carries the NEW kid.
- `MIK-7417.SEC3.2` — Given a rotation, When the successor kid is chosen, Then it is
  `minting_kid.wrapping_add(1)` and never the lowest free slot.
- `MIK-7417.SEC3.3` — Given an envelope sealed under a kid that has since been retired,
  When it is opened at any instant within `CONTINUATION_LIFETIME_SECS` of its issue,
  Then it opens — the retained key still verifies.
- `MIK-7417.SEC3.4` — Given a retained key whose retirement is more than
  `CONTINUATION_LIFETIME_SECS` behind `now`, When the next `mint` runs, Then the key is
  dropped from the ring and an envelope bearing its kid is refused with the no-such-kid
  reason rather than a decryption failure. Pruning is memory hygiene: no invariant rides on
  it, and the refusal itself belongs to `.15`.
- `MIK-7417.SEC3.5` — Given any sequence of `open` calls, When they return, Then neither
  `keys` nor `minting_kid` has changed (design invariant 5).
- `MIK-7417.SEC3.6` — Given a freshly constructed `ContinuationState` whose startup key
  has no `created_at`, When the FIRST `mint` runs, Then `created_at` is stamped from that
  mint's `now` and NO rotation occurs — a fresh replica does not burn a kid on request one.
- `MIK-7417.SEC3.7` — Given a rotation, When it completes, Then the new key's counter is
  reset to 0 BEFORE the triggering mint draws its slot, so that mint returns with the
  counter at exactly 1 (design invariant 4). Asserting 0 after the mint returns would fail
  a correct implementation — rotation happens inside `mint`, and that mint then seals.
- `MIK-7417.SEC3.8` — Given a minting key whose counter has drawn every slot within
  `budget`, When a further `mint` draws a slot past it, Then that mint FAILS and the ring
  does NOT rotate — budget exhaustion is a refusal, never a rotation trigger.
- `MIK-7417.SEC3.9` — Given a rotation whose successor kid is somehow still live, When
  the rotation runs, Then the mint SUCCEEDS under the current minting key and the event is
  logged — key hygiene never fails a continuation the user is waiting on.
- `MIK-7417.SEC3.10` — Given a rotation, When it completes, Then exactly one log line is
  emitted carrying the old kid, the new kid, and the retained-key count.
- `MIK-7417.SEC3.11` — Given any observable state of the ring, When it is read, Then
  `minting_kid` is a member of `keys` (design invariant 1).
- `MIK-7417.SEC3.12` — Given two mints arriving either side of the interval boundary,
  When both run, Then EXACTLY ONE rotation occurs — the age is re-checked under the write
  guard, so a racing set does not burn two kids.
- `MIK-7417.SEC3.13` — Given the shipped constants, When
  `256 * CONTINUATION_ROTATION_SECS > CONTINUATION_LIFETIME_SECS` is evaluated, Then it
  holds — the bound that keeps a returning kid outside the live window.
- `MIK-7417.SEC3.14` — Given the cross-`AppState` MRTR.5 regression that already exists as
  `a_token_minted_by_one_app_state_is_refused_by_another`
  (`tests/mik_7312_continuation_state.rs:145`), When rotation lands, Then it still passes AND
  the first `AppState` is shown to have rotated at least once inside the case — a regression
  that stays green because rotation never fired proves isolation, not rotation.
- `MIK-7417.SEC3.15` — Given a key whose retention window has passed and where NO mint has
  run to evict it, When an envelope sealed under it is opened, Then it is refused as
  EXPIRED and the key is still present in the ring — design invariant 2 is a property of
  the deadline check, and eviction is memory hygiene with no invariant riding on it.
- `MIK-7417.SEC3.16` — Given a minting kid of 255, When rotation runs, Then the successor
  is kid 0 — the only input on which `wrapping_add(1)` and a plain `+ 1` disagree.
- `MIK-7417.SEC3.17` — Given a minting key with exactly one slot left within `budget`, When
  several mints run concurrently, Then exactly one succeeds, every other fails with the
  budget error, and no rotation occurs — the slot draw is atomic, so the per-key sealing
  limit is a limit and not an average.


## Coverage matrix

| AC | case | V-model level | type | evidence |
|---|---|---|---|---|
| `.1` | mint at `created_at + ROTATION_SECS + 1` seals under a kid the caller did not hold before | unit | functional | *(none — to be written)* |
| `.2` | rotate from a ring where a LOWER kid is free; assert the successor is `prev + 1`, not the free slot | unit | functional | *(none — to be written)* |
| `.3` | seal, rotate, open at `issued_at + LIFETIME_SECS - 1` | unit | functional | *(none — to be written)* |
| `.4` | seal, rotate, advance past retention, mint to trigger eviction, open → no-such-kid reason | unit | negative | *(none — to be written)* |
| `.5` | snapshot `keys` + `minting_kid`, run opens (hit, miss, expired), assert both unchanged | unit | invariant | *(none — to be written)* |
| `.6` | first mint on a fresh `ContinuationState`: assert `created_at` equals that mint's injected `now`, kid unchanged, ring length still 1 | unit | boundary | *(none — to be written)* |
| `.7` | drive the pre-rotation counter high, rotate via `mint`, assert the new key's counter is exactly 1 — never the old value plus one | unit | invariant | *(none — to be written)* |
| `.8` | drive the counter past `budget` on a key too YOUNG to rotate; assert the error AND that the kid did not move | unit | negative | *(none — to be written)* |
| `.9` | ring pre-seeded so `prev + 1` is live on an overdue, under-budget key; assert the mint returns Ok under the OLD kid AND capture the fallback event's fields on the same subscriber harness as `.10` | unit | fallback | *(none — to be written)* |
| `.10` | capture the tracing subscriber over one rotation; assert one line, three fields | unit | observability | *(none — to be written)* |
| `.11` | property test: arbitrary interleaving of mints/opens, assert membership after each | unit | property | *(none — to be written)* |
| `.12` | N threads mint at the boundary instant; assert kid advanced by exactly 1 | integration | concurrency | *(none — to be written)* |
| `.13` | `const` assertion on the two constants | unit | static | *(none — to be written)* |
| `.14` | existing cross-`AppState` refusal case re-run after rotation lands, with a rotation forced inside it | system | regression | `tests/mik_7312_continuation_state.rs:145` (exists; must still pass) |
| `.15` | seal, retire, advance past retention WITHOUT minting, open → `Expired`; assert the key is still in the ring | unit | negative | *(none — to be written)* |
| `.16` | drive the ring to minting kid 255, rotate, assert the successor is 0 | unit | boundary | *(none — to be written)* |
| `.17` | N concurrent mints against one remaining slot; assert one `Ok`, N-1 budget errors, kid unmoved | integration | concurrency | *(none — to be written)* |

Sixteen empty cells, one filled. That ratio IS the plan's finding: the multi-key rings
that already exist at `tests/mik_7212_acs.rs:195-245` are hand-built, so they observe
`open`'s kid selection and nothing about rotation, retention or the counter discipline.

## §P2 Q2 — can each case actually FAIL?

Asked per row, because a case whose fixture makes its own assertion true passes every
coverage check ever devised.

| AC | what would make it unfalsifiable | how this plan avoids it |
|---|---|---|
| `.1` | a fixture that hand-inserts the second key, so the assertion holds whether or not `mint` rotates | the ring is built ONLY by `ContinuationState::new`; the second kid may exist only because `mint` made it |
| `.2` | asserting `new_kid != old_kid`, which the lowest-free-slot rule also satisfies | the ring is seeded so the lowest free slot is NOT `prev + 1`; the two rules give different answers and the assertion names one |
| `.3` | opening at `issued_at`, where retention is not yet load-bearing | the instant is `issued_at + LIFETIME_SECS - 1`, one second inside the boundary the criterion names |
| `.4` | asserting "refused", which an expiry check alone also delivers | the assertion is on the REASON. By the design's arithmetic no UNEXPIRED envelope under an evictable kid can exist, so staging one would mean hand-writing a lying deadline — the fixture authoring its own assertion. The case works instead because kid resolution precedes the deadline check (`src/protocol/continuation.rs:489`, before `:508`): drop eviction and the identical fixture answers `Expired`, and the row goes red |
| `.5` | opens that all miss, so no mutation was ever plausible | three opens: a hit, a miss, and an expired-payload hit, so the mutating path is exercised |
| `.6` | a fresh state whose key already carries a `created_at`, making "no rotation" vacuous | the startup key is asserted to have NO stamp before the mint and the stamp is then asserted BY VALUE against the injected `now`. If `created_at` is not readable from a test, exposing it is this plan's obligation before the case is written — kid-unchanged plus length-1 is satisfied vacuously by any fixture |
| `.7` | reading `minted` before any mint has drawn a slot | the pre-rotation key is driven to a HIGH counter first, so 1 afterwards is a reset plus one draw rather than a carried count; the assertion names the value observable when `mint` returns, which is where a test can actually look |
| `.8` | a key old enough to rotate, letting a rotation reset the counter and mask the refusal | the key is deliberately YOUNG; only the budget can decide, and the kid assertion catches a rotation |
| `.9` | a fixture where the mint would have succeeded anyway | the live successor is pre-seeded on a key that IS overdue and under budget, so the fallback branch is the only path to Ok; and the log conjunct is asserted rather than assumed, so a silent fallback fails the row |
| `.10` | asserting "a log line exists" | the three field VALUES are asserted, and one line means a second rotation would fail the count |
| `.11` | a property test over inputs that never rotate | the generator's time steps straddle `ROTATION_SECS` AND the harness counts rotations, requiring at least one per run; a run that never rotated is inconclusive, not green |
| `.12` | threads serialised by the harness, so no race exists | the assertion is on the OUTCOME (`+1`), correct under serialisation too; the case earns its keep by going red when the second age check under the write guard is removed — that mutation is its falsifier, run as a `cargo-mutants` target rather than argued in prose (DoD §4 wants the tool's output). Both callers are held until each has observed the rotation as due and then released, so the interleaving the row cares about is forced, not hoped for |
| `.13` | none — a `const` assertion cannot be staged | it goes red the moment either constant is edited past the bound; that is its whole job |
| `.14` | the existing case passing because rotation never touched it | rotation changes the ring's shape on the minting side; the case is re-run, not re-asserted, and its failure mode is a token that starts being ACCEPTED cross-state |
| `.15` | asserting "refused", which the no-such-kid path also delivers | the assertion is `Expired` AND the key still being in the ring; an implementation that evicted eagerly fails the second half, one that skips the deadline check fails the first |
| `.16` | folding the wrap into `.2`, where `prev + 1` and `wrapping_add` agree | 255 is the only input on which the two rules differ, and a plain `+ 1` panics there in debug — the case goes red loudly, not subtly |
| `.17` | a harness that serialises the callers, where no two draws ever share a slot | the assertion counts OUTCOMES, not schedules, so it is correct under serialisation and red whenever a read-then-write interleaving lands; its named falsifier is splitting the counter's read and increment across the guard boundary |


Rows `.12` and `.17` are the honest weak ones and are marked as such: a concurrency
assertion is proved by mutation, not by observation. Both name their falsifier as a
`cargo-mutants` target rather than assuming it.

## Out of scope

Operator-supplied key material, cross-replica portability, session affinity, and any
shared store — all four excluded by the design's own scope statement. No wire change:
`VERSION` stays 1, so there is no protocol-compatibility row (C14). T1c is N/A: the
envelope is symmetric AES-256-GCM, and the DoR's T1c reads *"FAST-PATH: symmetric-only
(HMAC,AES,ChaCha)=auto-PASS"*
(`/Users/mikko/github/claude-elite-live/rules-source/workflows/quality-gates-dor.md`).

## DoD §4 commitments this plan takes on

Stated here so they are obligations rather than after-the-fact justifications: rotation and
retention are security-path code, so **coverage is the Critical tier, >=95%**, and
**mutation score >=85% on the new rotation code**, evidenced by `cargo-mutants` output.
Two rows (`.12`, `.17`) already rest on named mutants; this makes the gate general.
