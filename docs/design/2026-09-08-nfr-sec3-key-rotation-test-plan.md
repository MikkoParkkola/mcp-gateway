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
  reason rather than a decryption failure.
- `MIK-7417.SEC3.5` — Given any sequence of `open` calls, When they return, Then neither
  `keys` nor `minting_kid` has changed (design invariant 5).
- `MIK-7417.SEC3.6` — Given a freshly constructed `ContinuationState` whose startup key
  has no `created_at`, When the FIRST `mint` runs, Then `created_at` is stamped from that
  mint's `now` and NO rotation occurs — a fresh replica does not burn a kid on request one.
- `MIK-7417.SEC3.7` — Given a rotation, When it completes, Then the new key's `minted`
  counter reads 0 (design invariant 4).
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

## Coverage matrix

| AC | case | V-model level | type | evidence |
|---|---|---|---|---|
| `.1` | mint at `created_at + ROTATION_SECS + 1` seals under a kid the caller did not hold before | unit | functional | *(none — to be written)* |
| `.2` | rotate from a ring where a LOWER kid is free; assert the successor is `prev + 1`, not the free slot | unit | functional | *(none — to be written)* |
| `.3` | seal, rotate, open at `issued_at + LIFETIME_SECS - 1` | unit | functional | *(none — to be written)* |
| `.4` | seal, rotate, advance past retention, mint to trigger eviction, open → no-such-kid reason | unit | negative | *(none — to be written)* |
| `.5` | snapshot `keys` + `minting_kid`, run opens (hit, miss, expired), assert both unchanged | unit | invariant | *(none — to be written)* |
| `.6` | first mint on a fresh `ContinuationState`: kid unchanged, ring length still 1 | unit | boundary | *(none — to be written)* |
| `.7` | rotate, read the new key's `minted` | unit | invariant | *(none — to be written)* |
| `.8` | drive the counter past `budget` on a key too YOUNG to rotate; assert the error AND that the kid did not move | unit | negative | *(none — to be written)* |
| `.9` | ring pre-seeded so `prev + 1` is live; assert the mint returns Ok under the OLD kid | unit | fallback | *(none — to be written)* |
| `.10` | capture the tracing subscriber over one rotation; assert one line, three fields | unit | observability | *(none — to be written)* |
| `.11` | property test: arbitrary interleaving of mints/opens, assert membership after each | unit | property | *(none — to be written)* |
| `.12` | N threads mint at the boundary instant; assert kid advanced by exactly 1 | integration | concurrency | *(none — to be written)* |
| `.13` | `const` assertion on the two constants | unit | static | *(none — to be written)* |
| `.14` | existing cross-`AppState` refusal case re-run after rotation lands, with a rotation forced inside it | system | regression | `tests/mik_7312_continuation_state.rs:145` (exists; must still pass) |

Thirteen empty cells, one filled. That ratio IS the plan's finding: the multi-key rings
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
| `.4` | asserting "refused", which an expiry check alone also delivers | the assertion is on the REASON — no-such-kid, not expired — and the envelope is staged to be unexpired at the open instant |
| `.5` | opens that all miss, so no mutation was ever plausible | three opens: a hit, a miss, and an expired-payload hit, so the mutating path is exercised |
| `.6` | a fresh state whose key already carries a `created_at`, making "no rotation" vacuous | the startup key is asserted to have NO stamp before the mint, so the case can go red if `new` starts stamping |
| `.7` | reading `minted` before any mint has drawn a slot | the pre-rotation key is driven to a nonzero counter first, so 0 afterwards is a reset, not an initial value |
| `.8` | a key old enough to rotate, letting a rotation reset the counter and mask the refusal | the key is deliberately YOUNG; only the budget can decide, and the kid assertion catches a rotation |
| `.9` | a fixture where the mint would have succeeded anyway | the live successor is pre-seeded, so the fallback branch is the only path to Ok |
| `.10` | asserting "a log line exists" | the three field VALUES are asserted, and one line means a second rotation would fail the count |
| `.11` | a property test over inputs that never rotate | the generator's time steps straddle `ROTATION_SECS`, so rotations occur inside the run |
| `.12` | threads serialised by the harness, so no race exists | the assertion is on the OUTCOME (`+1`), correct under serialisation too; the case earns its keep by going red when the second age check under the write guard is removed — that mutation is its falsifier |
| `.13` | none — a `const` assertion cannot be staged | it goes red the moment either constant is edited past the bound; that is its whole job |
| `.14` | the existing case passing because rotation never touched it | rotation changes the ring's shape on the minting side; the case is re-run, not re-asserted, and its failure mode is a token that starts being ACCEPTED cross-state |

Row `.12` is the honest weak one and is marked as such: a concurrency assertion is proved
by mutation, not by observation. Its falsifier is named rather than assumed.

## Out of scope

Operator-supplied key material, cross-replica portability, session affinity, and any
shared store — all four excluded by the design's own scope statement. No wire change:
`VERSION` stays 1, so there is no protocol-compatibility row (C14). T1c is N/A: the
envelope is symmetric AES-256-GCM, which the DoR fast-paths.
