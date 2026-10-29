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

/// The per-user gateway under `security.posture: hardened` (test-only: every
/// `tools/call` is signed, its nonce in `_meta`), message signing armed,
/// alpha's own slot cold and lacking [`TOOL`], and [`TOOL`] surfaced per
/// `surfaced`.
async fn hardened_signed_gateway(surfaced: Surfaced) -> Gateway {
    super::slot_verdict_http_tests::gateway_tuned(
        (CallerSlot::Lacks, &valid(), Warmth::Cold),
        CLOSED,
        surfaced,
        (
            |_: &mut crate::config::BackendConfig| {},
            |meta: &mut crate::gateway::meta_mcp::MetaMcp| {
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
        ),
        |state: &mut super::AppState| {
            let mut config = (*state.live_config.running()).clone();
            config.security.posture = crate::security::SecurityPosture::Hardened;
            state.live_config = std::sync::Arc::new(crate::config_reload::LiveConfig::with_auth(
                config,
                std::sync::Arc::clone(state.live_config.generation().auth()),
            ));
        },
    )
    .await
}

/// A signed `tools/call` of [`TOOL`] by its own (surfaced) name, nonce in `_meta`.
async fn surfaced_call(gw: &Gateway, nonce: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
        "name": TOOL,
        "arguments": {"q": "x"},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            crate::gateway::meta_mcp::signing::NONCE_META: nonce,
        },
    }});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", TOOL)
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

/// W3 (MIK-8353 x MIK-8356, the seam pin): a signed surfaced call on a
/// per-user backend whose caller catalogue lacks the tool. The route-stage
/// verdict resolves (a mint) and lists alpha's cold slot (a fill), judging the
/// name absent; the call is answered as a name that matches no tool, through
/// the `_ =>` arm of `call_dispatch.rs` that asks for the nonce back. That
/// refund is safe only because the route-stage verdict dropped the witness
/// when it acted: the nonce stays spent. The control, a name nothing surfaces
/// (no verdict, nothing acted), gets it back through the same arm.
#[tokio::test]
async fn w3_http_an_absent_surfaced_name_after_a_verdict_act_keeps_the_nonce() {
    let control = hardened_signed_gateway(Surfaced::No).await;
    let first = surfaced_call(&control, "w3-control-n1").await;
    assert_eq!(
        first.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: a name nothing surfaces answers -32601: {first}"
    );
    assert_eq!(
        control.mints.load(Ordering::SeqCst),
        0,
        "premise: the control's call resolved nothing"
    );
    let again = surfaced_call(&control, "w3-control-n1").await;
    assert_eq!(
        again.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the re-sent control is answered as the absent name again: {again}"
    );
    assert!(
        !message(&again).contains(REPLAY),
        "premise: the `_ =>` arm gives an effect-free call's nonce back, else \
         this row cannot tell keep from refund: {again}"
    );

    let gw = hardened_signed_gateway(Surfaced::Yes).await;
    let lists = gw.caller.lists();
    let absent = surfaced_call(&gw, "w3-n1").await;
    assert_eq!(
        absent.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: alpha's catalogue lacks the tool, so it answers as absent: {absent}"
    );
    assert!(
        gw.mints.load(Ordering::SeqCst) > 0,
        "premise: the verdict resolved alpha's credential"
    );
    assert!(
        gw.caller.lists() > lists,
        "premise: the verdict listed alpha's cold slot"
    );
    assert_eq!(gw.dispatched(), 0, "premise: nothing reached the upstream");

    let resent = surfaced_call(&gw, "w3-n1").await;
    assert!(
        message(&resent).contains(REPLAY),
        "the nonce was given back after the verdict minted and listed: {resent}"
    );
}

/// [`invoke`] as a task-augmented call (the client declares the tasks
/// extension), under `key` and `nonce`.
async fn task_invoke(gw: &Gateway, key: &str, nonce: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": key}, "nonce": nonce},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {crate::gateway::meta_mcp::upstream::TASKS_EXTENSION: {}}
            },
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

/// P0 x MIK-8353 3c (KEEP): the route-stage verdict mints alpha's
/// credential for a task call, then sealed intake refuses the submit (409).
/// The refusal asks for the nonce back, but something acted and no veto is
/// set, so only the witness the verdict dropped keeps the nonce spent: a
/// give-back at the submit that skips the witness turns this red.
#[tokio::test]
async fn p0_http_a_verdict_mint_then_a_sealed_task_submit_keeps_the_nonce() {
    let mut executor = None;
    let gw = super::slot_verdict_http_tests::gateway_tuned(
        (CallerSlot::Valid, &valid(), Warmth::Warm),
        CLOSED,
        Surfaced::No,
        (
            |_: &mut crate::config::BackendConfig| {},
            |meta: &mut crate::gateway::meta_mcp::MetaMcp| {
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
        ),
        |state| executor = Some(std::sync::Arc::clone(&state.task_executor)),
    )
    .await;
    let executor = executor.expect("the fixture state");
    let admission = executor.service.admission();
    admission.adjust_sealed(0, 1);
    let refused = task_invoke(&gw, "p0-k1", "p0-n1").await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(409)),
        "premise: sealed intake's own refusal: {refused}"
    );
    assert!(
        gw.mints.load(Ordering::SeqCst) > 0,
        "premise: the verdict minted alpha's credential before the submit"
    );
    assert_eq!(gw.dispatched(), 0, "premise: nothing reached the upstream");
    admission.adjust_sealed(1, 0);

    let resent = task_invoke(&gw, "p0-k2", "p0-n1").await;
    assert!(
        message(&resent).contains(REPLAY),
        "the nonce was given back after the verdict minted: {resent}"
    );
}

#[path = "slot_verdict_witness_cooldown_tests.rs"]
mod cooldown;
