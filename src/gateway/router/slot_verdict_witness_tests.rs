// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 x MIK-8353: the caller verdict acts before the refund witness.
//!
//! The verdict (`invoke/caller_verdict.rs`) resolves the caller's credential
//! (a per-user mint) on a per-user backend. On `/mcp` it runs before the
//! witness is minted (`dispatch_tools_call.rs`), so a later refusal that holds
//! the witness, execution admission here, gives the nonce back after the mint.
//! MIK-8353 r3/r4: a nonce comes back only when nothing acted. KEEP rows: red
//! while the verdict's effect does not reach the witness.

use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::slot_verdict_http_tests::{CLOSED, Gateway, gateway_built};
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, CallerSlot, Surfaced, TOOL, Warmth, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

const REPLAY: &str = "Nonce replay detected";

/// The per-user gateway with message signing armed (nonce required).
async fn signed_gateway() -> Gateway {
    gateway_built(
        (CallerSlot::Valid, &valid(), Warmth::Warm),
        CLOSED,
        Surfaced::No,
        |_| {},
        |meta| {
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"witness-rows-signing-secret-at-least-32-bytes".to_vec(),
                    None,
                    "witness-rows".into(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
        },
    )
    .await
}

/// A keyed, signed `gateway_invoke` of alpha's per-user tool, sent as alpha.
async fn invoke(gw: &Gateway, key: &str, nonce: &str, q: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": q}, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
        },
    }});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    });
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn message(body: &Value) -> String {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// (a) /mcp: the verdict mints alpha's credential, then execution admission
/// refuses the call (its key reused for other arguments, 409). Something acted,
/// so the nonce stays spent: the honest call re-sent under it is a replay.
#[tokio::test]
async fn w1_http_a_verdict_mint_then_an_admission_refusal_keeps_the_nonce() {
    let gw = signed_gateway().await;
    let first = invoke(&gw, "w1-k1", "w1-n1", "x").await;
    assert!(
        first.get("error").is_none(),
        "premise: the first call ran: {first}"
    );
    let ran = gw.dispatched();
    let minted_before = gw.mints.load(Ordering::SeqCst);

    let refused = invoke(&gw, "w1-k1", "w1-n2", "other").await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(409)),
        "premise: execution admission's own refusal: {refused}"
    );
    assert!(
        gw.mints.load(Ordering::SeqCst) > minted_before,
        "premise: the refused call's verdict minted alpha's credential before admission"
    );
    assert_eq!(
        gw.dispatched(),
        ran,
        "premise: the refusal reached no upstream"
    );

    let resent = invoke(&gw, "w1-k2", "w1-n2", "other").await;
    assert!(
        message(&resent).contains(REPLAY),
        "the nonce was given back after the verdict minted: {resent}"
    );
}
