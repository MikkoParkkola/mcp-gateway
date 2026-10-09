// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Delivery of continuations this gateway minted (#2210).

use super::*;

/// #2210: the stdio dispatcher finalizes through this path with
/// `PreserveInputRequired`; a continuation this gateway minted survives it,
/// a same-shaped string it did not mint is refused.
#[test]
fn firewall_delivery_keeps_a_minted_continuation_and_refuses_a_foreign_one() {
    use crate::protocol::continuation::{ContinuationState, Payload, now_unix_secs};

    let fixture = Fixture::new(FirewallAction::Allow, true, true, false);
    let padding = "x".repeat(3000);
    let shape = regex::Regex::new(r"gh[pos]_[A-Za-z0-9]{36}").unwrap();
    let mint = |state: &ContinuationState| {
        (0..200_000)
            .find_map(|_| {
                let payload = Payload::mint(
                    "backend-a".into(),
                    Some(padding.clone()),
                    "principal".into(),
                    "digest".into(),
                    "replica".into(),
                    "hold".into(),
                    now_unix_secs(),
                );
                let token = state
                    .keyring()
                    .mint(&payload)
                    .expect("a fresh payload seals");
                shape.is_match(&token[16..]).then_some(token)
            })
            .expect("ciphertext holds a credential-shaped run")
    };
    let deliver = |token: &str| {
        fixture.finalize(
            "tools/call",
            JsonRpcResponse::success(
                RequestId::Number(-41),
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"q1": {"params": {"message": "Choose"}}},
                    "requestState": token,
                }),
            ),
            &targets(),
        )
    };

    let own = mint(&fixture.meta.continuation());
    let delivered = deliver(&own);
    assert!(!delivered.delivery_refusal);
    assert_eq!(delivered.result.unwrap()["requestState"], own);

    let foreign = mint(&ContinuationState::new());
    assert!(deliver(&foreign).delivery_refusal);
}
