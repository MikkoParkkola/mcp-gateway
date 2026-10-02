// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The hardened direct route (`GH1942.HARDEN.1` row 7): under
//! `security.posture: hardened` with message signing armed, `/mcp/{backend}`
//! `tools/call` is admitted on a nonce and signed, as `gateway_invoke` is. The
//! guard cells cover the standard posture, where signing refuses the route.

use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::gateway::meta_mcp::signing::NONCE_META;
use crate::gateway::router::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed, send};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];

/// `tools/call read` on `backend` with `meta` as `params._meta`.
async fn call(fx: &Fx, backend: &str, meta: Value) -> (StatusCode, Value) {
    let params = json!({"name": "read", "arguments": {}, "_meta": meta});
    send(
        fx,
        &format!("/mcp/{backend}"),
        "k-std",
        "tools/call",
        params,
        None,
    )
    .await
}

fn nonce_meta(nonce: &str) -> Value {
    json!({ NONCE_META: nonce })
}

#[tokio::test]
async fn a_hardened_direct_call_is_signed_and_its_nonce_cannot_replay() {
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::Ok, true).await;
        let nonce = format!("{backend}-nonce-1");
        let (status, body) = call(&fx, backend, nonce_meta(&nonce)).await;
        assert_eq!(status, StatusCode::OK, "{backend}: {body}");
        assert!(
            body["result"].get("_signature").is_some(),
            "{backend}: {body}"
        );
        assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "{backend}");

        let (status, body) = call(&fx, backend, nonce_meta(&nonce)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{backend} replay: {body}");
        assert!(body.get("result").is_none(), "{backend} replay: {body}");
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "{backend} replay dispatched"
        );
    }
}

#[tokio::test]
async fn a_hardened_direct_call_without_a_required_nonce_is_refused() {
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::Ok, true).await;
        let (status, body) = call(&fx, backend, json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{backend}: {body}");
        assert_eq!(body["error"]["code"], -32001, "{backend}: {body}");
        assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "{backend}");
    }
}

#[tokio::test]
async fn a_hardened_direct_call_with_a_malformed_nonce_is_refused() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let (status, body) = call(&fx, "alpha", json!({ NONCE_META: 5 })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_retained_result_is_signed_over_the_new_nonce() {
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::Ok, true).await;
        let meta = |nonce: &str| json!({ NONCE_META: nonce, IDEMPOTENCY_KEY_META: "k-signed" });
        let (n1, n2) = (format!("{backend}-n1"), format!("{backend}-n2"));
        let (_, first) = call(&fx, backend, meta(&n1)).await;
        let (status, again) = call(&fx, backend, meta(&n2)).await;
        assert_eq!(status, StatusCode::OK, "{backend}: {again}");
        // Each answer is signed over the nonce of its own request, so the
        // retained result carries a fresh signature, not the first one.
        assert_eq!(first["result"]["_signature"]["nonce"], n1, "{first}");
        assert_eq!(again["result"]["_signature"]["nonce"], n2, "{again}");
        assert_ne!(
            first["result"]["_signature"]["sig"], again["result"]["_signature"]["sig"],
            "{backend}: stale signature replayed"
        );
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "{backend} re-dispatched"
        );
    }
}
