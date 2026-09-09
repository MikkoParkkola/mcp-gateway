# Test plan — NFR.SEC.3 continuation key rotation

Design: `docs/design/2026-09-06-nfr-sec3-key-rotation.md` (ruled by R24 in
`docs/release/2026-09-08-team-lead-rulings.md`).
Implementation: `src/protocol/continuation.rs`.
Tests: `tests/nfr_sec3_key_rotation.rs`.

One row per acceptance criterion: the criterion, the case that proves it, and
why that case can genuinely fail. The last column is the one that matters — a
case whose fixture makes its own assertion true passes every coverage check
ever devised, and proves nothing.

## Scope

FOR: the continuation keyring rotates its minting key on an interval, keeps
retired keys long enough to open envelopes they sealed, and prunes them once
they cannot.

OUT: operator-supplied key material, cross-replica envelope portability,
session affinity, any shared or persistent key store, timers, watchers, config
reload, operator verbs. Each of those re-opens MRTR.5 and is refused here on
that ground, not on effort.

## V-model level and type

Every case is a component test at the `Keyring` public surface, driven through
`mint`, `open`, `minting_kid` and `retained_kid_count`. No case reaches into a
private field, because the criterion is about what an operator can observe: the
key id on the wire, and whether an envelope still opens. A test that read
private state would pass a refactor that broke the observable behaviour.

| AC | Criterion | Case | Why it can fail |
|---|---|---|---|
| `MIK-7417.SEC3.1` | The first mint after startup uses the startup key and does not rotate. | `first_mint_does_not_rotate` | `Keyring::new` has no clock, so the startup key's birth instant is `None`. A build reading that absence as zero makes the key infinitely old, and the first request burns a successor. The case mints at a large `now` — at a small one the arithmetic hides the defect. |
| `MIK-7417.SEC3.2` | A mint more than one rotation interval after the last rotation is sealed by a fresh key. | `rotation_happens_after_the_interval` | Two mints, `t` and `t + 61`, and the assertion reads byte 1 of the decoded envelope. A build that never rotates, or that rotates on the wrong clock, returns the same kid twice. |
| `MIK-7417.SEC3.3` | An envelope minted before a rotation still opens after it, inside the lifetime window. | `a_retired_key_still_opens_its_envelopes` | A build that drops the old key on rotation refuses honest traffic for the whole lifetime window, and the client cannot know which side of the rotation its envelope came from. The case opens the pre-rotation envelope after the rotation and reads its `issued_at` back. |
| `MIK-7417.SEC3.4` | Each rotation takes the successor id, never the lowest free one. | `successive_rotations_take_successive_ids` | Reusing a gap puts a kid back on the wire while a retained key still verifies with it, and `open` cannot tell the two envelopes apart. Four mints an interval apart must give exactly `1, 2, 3, 4`; a lowest-free-id build gives a repeat as soon as one is pruned. |
| `MIK-7417.SEC3.5` | A mint refused for budget does not rotate. | `budget_exhaustion_does_not_rotate` | Both mints are at the same instant, so rotation is not due. A build that rotates on the refusal path — or that charges the budget against the ring rather than the key — answers with a different kid or a different retained count. |
| `MIK-7417.SEC3.6` | A key retired longer ago than the lifetime is pruned. | `a_key_older_than_the_lifetime_is_pruned` | Without pruning the ring grows for the life of the process and eventually exhausts the one-byte id space. The case asserts the count through `retained_kid_count`; inferring it from a refused envelope would answer whether one key is gone, not whether pruning ran. |
| `MIK-7417.SEC3.7` | The id space outlasts the retention window. | No test case: a `const` assertion at `src/protocol/continuation.rs:146`. | `256 * rotation > lifetime` is what keeps `rotate_if_due` from meeting a successor that is still retained; violate it and rotation stops silently. A runtime test would assert a constant against mirrored copies of the same constants. The `const` block fails the BUILD instead, reading the real values — strictly stronger, so the case was eliminated rather than written. |

## Constants are mirrored, not imported

The test file restates `ROTATION_SECS` and `LIFETIME_SECS` as literals. The
module's constants are private, and a test that reads the value it is checking
cannot notice that value changing — the assertion would follow the edit. The
cost is that a deliberate change to either constant fails these tests, which is
the intended alarm and not a maintenance burden.

## Retrofitting

These tests are written against code that already exists, so they cannot use
the free failure of a test written first. Each was checked with the falsifier
probe: the defect reintroduced by hand, the suite run, the assertion read
(never the exit code), the file restored from a saved copy and the suite
re-run. The probe is a recovery mechanism for a process violation, not a step.
