// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7736: under `standard`, a `gateway_invoke` nonce is judged after the
//! invocation policy on the real `/mcp` route, as `prepare_signing_invocation`
//! orders it. A denied call gets the policy refusal and counts no nonce
//! rejection; an allowed one is still refused for its malformed nonce, once.
//!
//! The route is driven on a current-thread runtime inside the scoped metrics
//! recorder (`nonce_metrics_support::observe`), so every metric the request
//! emits is seen.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::message_signing::MessageSigner;
use crate::security::message_signing::nonce_metrics_support::{
    INVALID_REFUSAL, assert_no_rejections, assert_single_rejection, observe,
};

const SIGNING_SECRET: &[u8] = b"nonce-order-signing-secret-at-least-32-bytes";

/// Auth on, one key `k` scoped to backend `alpha`.
fn key_for_alpha() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            expires_at: None,
            name: "alpha-client".to_string(),
            rate_limit: 0,
            backends: vec!["alpha".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    }
}

/// The `standard` fixture with signing on, through the production entry point.
async fn signed_state() -> (Arc<AppState>, tempfile::TempDir) {
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&key_for_alpha()).await;
    let app = Arc::get_mut(&mut state).expect("the fixture state is exclusively owned");
    let mut meta = MetaMcp::new(Arc::clone(&app.backends));
    meta.enable_message_signing(
        MessageSigner::new(SIGNING_SECRET.to_vec(), None, "order".to_owned()),
        Duration::from_secs(300),
        false,
    );
    app.meta_mcp = Arc::new(meta);
    (state, store)
}

/// A `gateway_invoke` of `server` carrying a `null` nonce, the malformed shape.
fn invoke_with_null_nonce(server: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": server, "tool": "read", "arguments": {}, "nonce": null,
        }},
    })
    .to_string()
}

async fn post(state: Arc<AppState>, body: String) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer k")
        .body(axum::body::Body::from(body))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// One request on a current-thread runtime, observed by the scoped recorder.
fn observed(
    server: &str,
) -> (
    Value,
    Vec<crate::security::message_signing::nonce_metrics_support::Observed>,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (state, _store) = runtime.block_on(signed_state());
    let ((_, body), events) =
        observe(|| runtime.block_on(post(state, invoke_with_null_nonce(server))));
    (body, events)
}

/// R1 (the ticket's fail-fast, route level): a denied `gateway_invoke` with a
/// malformed nonce gets the policy refusal and counts no nonce rejection.
#[test]
fn a_denied_invoke_with_a_malformed_nonce_gets_the_policy_refusal() {
    let (body, events) = observed("beta");
    let error = &body["error"];
    assert!(error.is_object(), "the call is refused: {body}");
    assert_eq!(error["code"], json!(-32003), "policy answers first: {body}");
    assert_ne!(error["message"], json!(INVALID_REFUSAL), "{body}");
    assert_no_rejections(&events);
}

/// R2 (control): the same call, allowed by policy, is still refused for its
/// malformed nonce, and counted once.
#[test]
fn an_allowed_invoke_with_a_malformed_nonce_is_still_refused_and_counted() {
    let (body, events) = observed("alpha");
    assert_eq!(body["error"]["code"], json!(-32602), "{body}");
    assert_eq!(body["error"]["message"], json!(INVALID_REFUSAL), "{body}");
    assert_single_rejection(&events, "invalid");
}
