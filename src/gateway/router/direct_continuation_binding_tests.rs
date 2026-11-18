// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R19: the propagated binding.

use super::*;

/// R19 (both routes): a continuation binds a caller as the idempotency guard
/// does, the propagated binding first, so one verified identity presenting
/// another binding (another backend credential) cannot redeem it. Mutant: the
/// verified identity bound ahead of the binding (each route).
#[tokio::test]
async fn r19_the_propagated_binding_binds_ahead_of_the_identity() {
    use crate::protocol::mrtr::source_fingerprint;
    let fx = fixture(Answer::Ok, |_| {}).await;
    let meta = &fx.state.meta_mcp;
    let alice = identity("alice");
    let who = |binding| (Some(&alice), (Some(binding), None), None);
    let sent = json!({"name": "read", "arguments": {}});
    let mut asked = json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {"method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}}},
        "requestState": BACKEND_STATE
    });
    // A client that declared form elicitation, so the question may be asked
    // (MRTR.9).
    let declared = crate::protocol::meta::Declared::from_handshake(Some(
        &json!({"elicitation": {"form": {}}}),
    ));
    meta.seal_direct_interim(
        who("binding-a"),
        ("alpha", None, Some(&sent), declared),
        &mut asked,
    )
    .await
    .expect("sealed");
    let retry = json!({"name": "read", "arguments": {},
        "requestState": asked["requestState"], "inputResponses": answers()});
    let mut outbound = retry.clone();
    meta.redeem_direct_retry(
        who("binding-b"),
        ("alpha", None, Some(&retry)),
        &mut outbound,
    )
    .await
    .expect_err("another binding redeemed it");
    meta.redeem_direct_retry(
        who("binding-a"),
        ("alpha", None, Some(&retry)),
        &mut outbound,
    )
    .await
    .expect("its own binding redeems it");
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: Some(&alice),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let bound = |binding| source_fingerprint(caller.principal_source(Some(binding)));
    assert_ne!(bound("binding-a"), bound("binding-b"), "meta");
}
