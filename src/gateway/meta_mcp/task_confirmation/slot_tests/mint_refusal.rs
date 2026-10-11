// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S6b: a refused confirmation mint gives its slot back. Moved out of
//! `slot_tests.rs` unchanged, to keep that file under the 800-line ceiling.

use super::*;

/// S6b (MIK-8311 CSL.1): a task confirmation whose envelope mint fails gives
/// its slot back. The keyring refuses every envelope, so the gate takes a
/// slot, cannot seal the grant, and refuses; the slot must not stay held for
/// the envelope's lifetime. Red on base: the slot count grows by one.
/// Mutant m8: the release on the mint-failure path removed.
#[tokio::test]
async fn s6b_a_refused_confirmation_mint_gives_its_slot_back() {
    let mut fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    fx.meta.set_continuation_for_test(
        crate::protocol::continuation::ContinuationState::mint_refusing_for_test(),
    );
    let now = crate::protocol::continuation::now_unix_secs();
    let before = fx.meta.continuation.in_flight().len(now).await;

    let outcome = ask(&fx, &fresh(), elicitation()).await;
    let TaskConfirmation::Answer(response) = &outcome else {
        panic!("setup: the gate did not answer: {outcome:?}");
    };
    assert!(
        response.error.is_some(),
        "setup: a refused mint must refuse, got {response:?}"
    );

    let after = fx.meta.continuation.in_flight().len(now).await;
    assert_eq!(
        after, before,
        "the refused confirmation kept its slot: {before} held before, {after} after"
    );
}
