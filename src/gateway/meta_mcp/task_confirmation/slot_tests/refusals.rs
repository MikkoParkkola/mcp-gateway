// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusals the destructive task gate answers with, and the grant it redeems.

use super::*;

/// A caller with neither an identity nor a key is still
/// refused as unbindable once key-only callers can be bound: binding the key
/// must not turn "no principal" into "everyone is one principal".
#[tokio::test]
async fn a_caller_with_no_identity_and_no_key_is_refused_as_unbindable() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (code, message) = refusal(&ask_as(&fx, &fresh(), elicitation(), None).await);
    assert_eq!(code, -32003, "{message}");
    assert_eq!(message, X14_UNBINDABLE);
}

/// X14's whole refusal for a caller it cannot bind a confirmation to: the one
/// witness of that `-32003` text (`task_confirmation.rs`).
const X14_UNBINDABLE: &str =
    "this destructive call cannot be confirmed for a caller this gateway cannot name";

fn refusal(outcome: &TaskConfirmation) -> (i32, String) {
    let TaskConfirmation::Answer(response) = outcome else {
        panic!("expected a refusal, got {outcome:?}");
    };
    assert!(
        response.result.is_none(),
        "a refusal is no result: {response:?}"
    );
    let error = response.error.as_ref().expect("a refusal is an error");
    (error.code, error.message.clone())
}

/// Mutant: the undeclared-capability refusal for a known destructive tool is
/// dropped, or reworded to claim the tool is unclassified.
#[tokio::test]
async fn a_destructive_call_from_a_client_that_cannot_be_asked_is_refused() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (code, message) = refusal(&ask(&fx, &fresh(), Declared::NONE).await);
    assert_eq!(code, -32021);
    assert!(message.contains("is destructive"), "{message}");
    assert!(!message.contains("could not be classified"), "{message}");
    // Positive control: the same call from a client that declared it can be asked.
    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// Mutant: a full hold table still mints a grant naming an exchange nobody holds.
#[tokio::test]
async fn a_full_hold_table_refuses_the_challenge_and_mints_no_grant() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let now = crate::protocol::continuation::now_unix_secs();
    let table = fx.meta.continuation.in_flight();
    let mut held = Vec::new();
    // A caller per hold: the table fills, not one caller's share.
    while let Some(key) = table
        .hold(
            "filler",
            &crate::protocol::continuation::QuotaKey::for_test(&format!("filler-{}", held.len())),
            now + 300,
            now,
        )
        .await
    {
        held.push(key);
        assert!(held.len() <= 1 << 16, "the hold table is bounded");
    }
    assert!(!held.is_empty());
    assert_eq!(refusal(&ask(&fx, &fresh(), elicitation()).await).0, -32003);

    // Positive control: one freed slot and the same call is asked again.
    assert!(table.complete(&held[0], now).await);
    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// Mutant: a mint failure is answered with a challenge, or with the grant.
#[tokio::test]
async fn a_grant_that_cannot_be_sealed_refuses_the_challenge() {
    // The backend's name is sealed into the envelope; one this long exceeds
    // the envelope bound, which is how a mint refuses.
    let long = "b".repeat(16 * 1024);
    let fx = fixture_on(&long, BackendConfig::default(), Some(Hint::Destructive)).await;
    assert_eq!(refusal(&ask(&fx, &fresh(), elicitation()).await).0, -32003);

    // Positive control: an ordinary name seals.
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    challenge(&ask(&fx, &fresh(), elicitation()).await);
}

/// Mutant: the hold check removed, so a grant for an exchange this replica no
/// longer holds is honoured, or the refusal also burns the caller's redemption.
#[tokio::test]
async fn a_grant_whose_hold_is_gone_is_refused_without_spending_it() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (retry, payload) = accepted_challenge(&fx).await;
    let now = crate::protocol::continuation::now_unix_secs();
    assert!(
        fx.meta
            .continuation
            .in_flight()
            .complete(&payload.hold_key, now)
            .await
    );
    assert_eq!(refusal(&ask(&fx, &retry, elicitation()).await).0, -32602);
    assert!(
        fx.meta
            .continuation
            .ledger()
            .consume(&payload.jti, payload.expires_at, now)
            .await,
        "the refusal came before the spend"
    );

    // Positive control: a grant whose hold is still live is granted.
    let (live, _) = accepted_challenge(&fx).await;
    assert!(matches!(
        ask(&fx, &live, elicitation()).await,
        TaskConfirmation::Granted(_)
    ));
}

/// Mutant: the spent check removed, so one grant is redeemed twice.
#[tokio::test]
async fn a_grant_already_spent_is_refused_and_a_fresh_one_is_granted_once() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let (retry, payload) = accepted_challenge(&fx).await;
    let now = crate::protocol::continuation::now_unix_secs();
    assert!(
        fx.meta
            .continuation
            .ledger()
            .consume(&payload.jti, payload.expires_at, now)
            .await
    );
    assert_eq!(refusal(&ask(&fx, &retry, elicitation()).await).0, -32602);

    // Positive control: an unspent grant is granted, and only once.
    let (retry, _) = accepted_challenge(&fx).await;
    assert!(matches!(
        ask(&fx, &retry, elicitation()).await,
        TaskConfirmation::Granted(_)
    ));
    assert_eq!(refusal(&ask(&fx, &retry, elicitation()).await).0, -32602);
}

/// #3616 regression: a destructive call on a clock before 1970 is
/// refused, never challenged: no confirmation is minted against a time the
/// gateway cannot read. Control: the real clock challenges the same call.
#[tokio::test]
async fn a_destructive_call_on_a_clock_before_the_epoch_is_refused() {
    let fx = fixture(BackendConfig::default(), Some(Hint::Destructive)).await;
    let refused = {
        let _clock = crate::clock::test_clock::before_epoch();
        ask(&fx, &fresh(), elicitation()).await
    };
    let TaskConfirmation::Answer(response) = &refused else {
        panic!("a clock before 1970 challenged a destructive call: {refused:?}");
    };
    let error = response.error.as_ref().expect("a refusal is an error");
    assert_eq!(error.code, -32003, "{error:?}");
    assert!(response.result.is_none(), "a refusal carries no challenge");

    challenge(&ask(&fx, &fresh(), elicitation()).await);
}
