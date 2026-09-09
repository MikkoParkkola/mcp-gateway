// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Continuation key rotation — NFR.SEC.3.
//!
//! Test plan: `docs/requirements/2026-09-09-nfr-sec3-key-rotation-test-plan.md`.
//! Design: `docs/design/2026-09-06-nfr-sec3-key-rotation.md`.
//!
//! Every case here drives `Keyring` through its public surface only, because
//! that is the surface the criterion is about: an operator can observe which
//! key sealed an envelope and which keys still open one, and nothing else.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use mcp_gateway::protocol::continuation::{Keyring, Payload};

/// One rotation interval, mirrored from the module under test.
///
/// Deliberately a literal rather than an import: the constant is private, and a
/// test that reads the value it is checking cannot notice the value changing.
const ROTATION_SECS: u64 = 60;
/// Likewise for the lifetime ceiling.
const LIFETIME_SECS: u64 = 300;

fn keyring() -> Keyring {
    Keyring::new(&[(1, [7u8; 32])]).expect("a single 32-byte key is a legal ring")
}

fn payload(now: u64) -> Payload {
    Payload {
        backend_id: "backend".to_string(),
        backend_request_state: None,
        principal_fingerprint: "fp".to_string(),
        original_request_digest: "digest".to_string(),
        origin_replica: "replica".to_string(),
        issued_at: now,
        expires_at: now + LIFETIME_SECS,
        jti: "jti".to_string(),
        hold_key: "hold".to_string(),
    }
}

/// The key id on the wire, which is what an operator can actually see.
fn kid_of(token: &str) -> u8 {
    let wire = B64.decode(token).expect("mint emits url-safe base64");
    wire[1]
}

#[test]
fn first_mint_does_not_rotate() {
    // The startup key has no birth instant until its first mint stamps one.
    // Read as zero it would be older than any plausible `now`, and the first
    // request after startup would burn a successor for nothing. A large `now`
    // is what makes that failure visible: at a small one the arithmetic hides.
    let ring = keyring();
    let token = ring.mint(&payload(1_800_000_000)).expect("mint");

    assert_eq!(kid_of(&token), 1, "the first mint must use the startup key");
    assert_eq!(ring.minting_kid(), 1);
    assert_eq!(ring.retained_kid_count(), 1, "nothing to retain yet");
}

#[test]
fn rotation_happens_after_the_interval() {
    let ring = keyring();
    let first = ring.mint(&payload(1_000)).expect("mint");
    let second = ring
        .mint(&payload(1_000 + ROTATION_SECS + 1))
        .expect("mint");

    assert_eq!(kid_of(&first), 1);
    assert_ne!(
        kid_of(&second),
        kid_of(&first),
        "a mint past the interval must be sealed by a fresh key"
    );
    assert_eq!(ring.minting_kid(), kid_of(&second));
}

#[test]
fn a_retired_key_still_opens_its_envelopes() {
    // The point of retention. An envelope minted a second before a rotation is
    // as valid as one minted a second after, and a client cannot know which it
    // holds. Dropping the old key on rotation would refuse honest traffic for
    // the whole lifetime window.
    let ring = keyring();
    let before = ring.mint(&payload(1_000)).expect("mint");
    let _after = ring
        .mint(&payload(1_000 + ROTATION_SECS + 1))
        .expect("mint");

    let opened = ring
        .open(&before, 1_000 + ROTATION_SECS + 2)
        .expect("an envelope from the retired key must still open");
    assert_eq!(opened.issued_at, 1_000);
    assert_eq!(ring.retained_kid_count(), 2, "the retired key is kept");
}

#[test]
fn successive_rotations_take_successive_ids() {
    // Never the lowest free id. Reusing a gap would put a kid back on the wire
    // while a retained key still verifies with it, and the two envelopes would
    // be indistinguishable to `open`.
    let ring = keyring();
    let mut kids = Vec::new();
    for step in 0..4u64 {
        let token = ring
            .mint(&payload(1_000 + step * (ROTATION_SECS + 1)))
            .expect("mint");
        kids.push(kid_of(&token));
    }

    assert_eq!(kids, vec![1, 2, 3, 4], "each rotation takes the successor");
}

#[test]
fn budget_exhaustion_does_not_rotate() {
    // A refusal is not a reason to spend a key id. Both mints are at the same
    // instant, so rotation is not due; a build that rotated on the refusal path
    // would answer with a different kid.
    let ring = keyring().with_mint_budget(1);
    let first = ring.mint(&payload(1_000)).expect("the first mint fits");
    let second = ring.mint(&payload(1_000));

    assert!(second.is_err(), "the second mint exceeds the budget");
    assert_eq!(kid_of(&first), 1);
    assert_eq!(ring.minting_kid(), 1, "a refused mint rotates nothing");
    assert_eq!(ring.retained_kid_count(), 1);
}

#[test]
fn a_key_older_than_the_lifetime_is_pruned() {
    // Retention is bounded, or the ring grows for the life of the process. A
    // key retired longer ago than any envelope can still be redeemed cannot
    // open anything, so keeping it buys nothing and costs a slot.
    let ring = keyring();
    ring.mint(&payload(1_000)).expect("mint");
    ring.mint(&payload(1_000 + ROTATION_SECS + 1))
        .expect("mint");
    assert_eq!(ring.retained_kid_count(), 2, "still inside the window");

    ring.mint(&payload(1_000 + ROTATION_SECS + 2 + LIFETIME_SECS))
        .expect("mint");
    // Two before and two after is NOT a vacuous assertion, though it skims as
    // one. The third mint rotates, which would make three retained keys; the
    // count holds at two only because the same pass drops the key retired
    // beyond the lifetime. A build that rotated without pruning reads three
    // here, which is the regression this line exists to catch.
    assert_eq!(
        ring.retained_kid_count(),
        2,
        "the key retired beyond the lifetime is dropped, not accumulated"
    );
}

// There is deliberately no case for "the id space outlasts the retention
// window". `src/protocol/continuation.rs` asserts it in a `const` block, which
// fails the BUILD rather than a run — strictly stronger than anything a test
// here could do, and it reads the real constants instead of the mirrors above.
