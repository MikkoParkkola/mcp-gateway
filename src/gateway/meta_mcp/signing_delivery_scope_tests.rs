// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 9 (signing leg): the scope is settled before the
//! MAC is computed, so the signature covers the bytes actually delivered.

use super::{NONCE, SigningInvocationContext, finalize, meta, verify};
use crate::protocol::{JsonRpcResponse, RequestId};
use serde_json::{Value, json};

#[tokio::test]
async fn a_public_result_is_signed_as_private_and_verifies_as_delivered() {
    let original = JsonRpcResponse::success(
        RequestId::Number(-41),
        json!({"content": [{"type": "text", "text": "x"}], "cacheScope": "public"}),
    );

    let delivered = finalize(
        &meta(true, true),
        original,
        Some(&SigningInvocationContext::external_for_test(Some(NONCE))),
    )
    .await;

    let in_memory = delivered.result.as_ref().expect("a signed result");
    assert_eq!(in_memory["cacheScope"], "private", "clamped before signing");
    verify(&delivered, Some(NONCE)).expect("MAC verifies over the delivered bytes");
    let wire: Value = serde_json::from_str(&serde_json::to_string(&delivered).unwrap()).unwrap();
    assert_eq!(wire["result"]["cacheScope"], "private");
    assert!(wire["result"]["_signature"].is_object(), "{wire}");
}

#[tokio::test]
async fn a_direct_route_delivery_is_signed_as_private_and_verifies_as_delivered() {
    let mut delivered = JsonRpcResponse::success(
        RequestId::Number(-41),
        json!({"content": [], "cacheScope": "public"}),
    );

    meta(true, true).sign_direct_delivery(&mut delivered, Some(NONCE));

    assert_eq!(delivered.result.as_ref().unwrap()["cacheScope"], "private");
    verify(&delivered, Some(NONCE)).expect("MAC verifies over the delivered bytes");
}
