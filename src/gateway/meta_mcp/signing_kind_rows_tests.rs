// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The kind a refusal notes, read where it is noted: a nonce store at either
//! capacity refuses a single-use token, noted `replay_guard`; a chained
//! answer with no challenge on record fails the signature-chain check, noted
//! `signature_chain`. Each kind is compared as the record spells it.

use serde_json::json;

use super::meta;
use crate::gateway::meta_mcp::invoke::audit::{take_refusal_kind, with_route_scope};

/// The noted kind, spelled as a record spells it; `null` when none was noted.
fn spelled(kind: Option<crate::security::decision_record::DecisionKind>) -> serde_json::Value {
    serde_json::to_value(kind).expect("a kind serializes")
}

/// T3: one principal fills its share of the store. Its last free place is
/// admitted; the next nonce is refused for capacity, with the replay's code,
/// and notes `replay_guard`.
#[tokio::test]
async fn t3_a_principal_at_capacity_notes_replay_guard() {
    let meta = meta();
    let (last_admitted, refused, kind) = with_route_scope(async {
        for n in 0..9_999 {
            meta.admit_signing_nonce(Some(&format!("t3-{n}")), "t3-principal")
                .expect("below the principal's share");
        }
        let last = meta.admit_signing_nonce(Some("t3-last"), "t3-principal");
        let over = meta.admit_signing_nonce(Some("t3-over"), "t3-principal");
        (last.is_ok(), over, take_refusal_kind())
    })
    .await;
    assert!(last_admitted, "the 10000th nonce is within the share");
    let error = refused.expect_err("the 10001st nonce is over the share");
    assert_eq!(error.to_rpc_code(), -32001, "{error}");
    assert!(
        error
            .to_string()
            .contains("Signing nonce capacity exceeded"),
        "{error}"
    );
    assert_eq!(spelled(kind), json!("replay_guard"));
}

/// T3b: the store as a whole fills, spread over principals so that none
/// reaches its own share first; the next nonce notes `replay_guard`.
#[tokio::test]
async fn t3b_a_full_store_notes_replay_guard() {
    let meta = meta();
    let (refused, kind) = with_route_scope(async {
        for n in 0..100_000 {
            let principal = format!("t3b-{}", n % 20);
            meta.admit_signing_nonce(Some(&format!("t3b-{n}")), &principal)
                .expect("below every limit");
        }
        let over = meta.admit_signing_nonce(Some("t3b-over"), "t3b-fresh");
        (over, take_refusal_kind())
    })
    .await;
    let error = refused.expect_err("the store is full");
    assert_eq!(error.to_rpc_code(), -32001, "{error}");
    assert!(
        error
            .to_string()
            .contains("Signing nonce capacity exceeded"),
        "{error}"
    );
    assert_eq!(spelled(kind), json!("replay_guard"));
}

/// Control for T3 and T3b: a nonce seen once is refused as a replay and
/// notes the same kind, so the kind names the check, not the cause.
#[tokio::test]
async fn a_replayed_nonce_notes_replay_guard() {
    let meta = meta();
    let (refused, kind) = with_route_scope(async {
        meta.admit_signing_nonce(Some("seen"), "replay-principal")
            .expect("a fresh nonce");
        let again = meta.admit_signing_nonce(Some("seen"), "replay-principal");
        (again, take_refusal_kind())
    })
    .await;
    let error = refused.expect_err("a nonce seen within the window");
    assert!(
        error.to_string().contains("Nonce replay detected"),
        "{error}"
    );
    assert_eq!(spelled(kind), json!("replay_guard"));
}

/// Control: an over-long nonce is the request's shape and stays `syntax`.
#[tokio::test]
async fn an_over_long_nonce_still_notes_syntax() {
    let meta = meta();
    let long = "n".repeat(257);
    let (refused, kind) = with_route_scope(async {
        let answer = meta.admit_signing_nonce(Some(&long), "shape-principal");
        (answer, take_refusal_kind())
    })
    .await;
    assert_eq!(refused.expect_err("too long").to_rpc_code(), -32602);
    assert_eq!(spelled(kind), json!("syntax"));
}

/// C2: a chained backend answered and no challenge is on record for the
/// dispatch: the chain check refuses it and notes `signature_chain`.
#[tokio::test]
async fn c2_a_chained_answer_with_no_challenge_notes_signature_chain() {
    use crate::config::ChainMode;
    use crate::gateway::chain_test_support::{KEY_ID, signer, trusted_self};
    use crate::gateway::meta_mcp::response_security::chain_receipt::ChainSlot;
    let mut chained = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    chained.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
    chained.set_chain_trust(8, trusted_self(), 300);
    let origins = [KEY_ID.to_owned()];
    let mut result = json!({"content": [{"type": "text", "text": "unchecked"}]});
    let slot = ChainSlot::default();
    let (outcome, kind) = with_route_scope(async {
        let outcome = chained.chain_receive(
            (ChainMode::Require, &origins, Some(KEY_ID)),
            (&mut result, None),
            None,
            &slot,
        );
        (outcome, take_refusal_kind())
    })
    .await;
    assert!(outcome.is_err(), "premise: refused with no challenge");
    assert_eq!(spelled(kind), json!("signature_chain"));
}
