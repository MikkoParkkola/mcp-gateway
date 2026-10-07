// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7736: under `standard`, a `gateway_invoke` nonce is judged after the
//! invocation policy on the real `/mcp` route, as `prepare_signing_invocation`
//! orders it. A denied call gets the policy refusal and counts no nonce
//! rejection; an allowed one is still refused for its malformed nonce, once.
//! On `/mcp` the denied call is answered by the router's scope check
//! (`authorize_tool_target`); `policy_refusal_is_not_counted_as_a_nonce_rejection`
//! pins the same order inside `prepare_signing_invocation`.
//!
//! MIK-7928: under `hardened` the order inverts: every `tools/call` is
//! signed, and a malformed nonce is refused before policy.
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
use crate::config::{ApiKeyConfig, ApiKeyKind, AuthConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::signing::SigningScope;
use crate::security::SecurityPosture;
use crate::security::message_signing::MessageSigner;
use crate::security::message_signing::nonce_metrics_support::{
    INVALID_REFUSAL, assert_no_rejections, assert_single_rejection, observe,
};

const SIGNING_SECRET: &[u8] = b"nonce-order-signing-secret-at-least-32-bytes";

/// Auth on, one key `k` of `kind` scoped to backend `alpha`.
fn key_for_alpha(kind: ApiKeyKind) -> AuthConfig {
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
            kind,
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    }
}

/// The fixture with signing on under `posture`, through the production entry
/// point. `hardened` refuses a shared key, so its caller holds a personal one.
async fn signed_state(posture: SecurityPosture) -> (Arc<AppState>, tempfile::TempDir) {
    let kind = match posture {
        SecurityPosture::Hardened => ApiKeyKind::Personal,
        SecurityPosture::Standard => ApiKeyKind::Shared,
    };
    let (mut state, store) =
        super::tests::test_router_app_state_with_auth(&key_for_alpha(kind)).await;
    let app = Arc::get_mut(&mut state).expect("the fixture state is exclusively owned");
    // The route reads the posture the process started with.
    let mut config = (*app.live_config.get()).clone();
    config.security.posture = posture;
    app.live_config = Arc::new(crate::config_reload::LiveConfig::new(config));
    let mut meta = MetaMcp::new(Arc::clone(&app.backends));
    meta.enable_message_signing(
        MessageSigner::new(SIGNING_SECRET.to_vec(), None, "order".to_owned()),
        Duration::from_secs(300),
        false,
    );
    meta.set_signing_scope(SigningScope::of(posture));
    app.meta_mcp = Arc::new(meta);
    (state, store)
}

/// A `gateway_invoke` of `server` carrying `nonce`; `null` is the malformed
/// shape. Under `hardened` it is a 2026-07-28 call: a legacy one is served
/// only inside a session.
fn invoke_with_nonce(posture: SecurityPosture, server: &str, nonce: &Value) -> String {
    let mut request = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": server, "tool": "read", "arguments": {}, "nonce": nonce,
        }},
    });
    if posture == SecurityPosture::Hardened {
        request["params"]["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
    }
    request.to_string()
}

async fn post(state: Arc<AppState>, posture: SecurityPosture, body: String) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer k");
    // The headers a 2026-07-28 call carries; without them it reads as legacy.
    if posture == SecurityPosture::Hardened {
        builder = builder
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke");
    }
    let request = builder.body(axum::body::Body::from(body)).unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    // A streamed answer carries the message on its `data:` line.
    let text = String::from_utf8_lossy(&bytes);
    let message = text
        .lines()
        .find_map(|line| line.strip_prefix("data:"))
        .unwrap_or(&text);
    (
        status,
        serde_json::from_str(message.trim()).unwrap_or(Value::Null),
    )
}

/// One request on a current-thread runtime, observed by the scoped recorder.
fn observed(
    posture: SecurityPosture,
    server: &str,
    nonce: &Value,
) -> (
    Value,
    Vec<crate::security::message_signing::nonce_metrics_support::Observed>,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (state, _store) = runtime.block_on(signed_state(posture));
    let ((_, body), events) = observe(|| {
        runtime.block_on(post(
            state,
            posture,
            invoke_with_nonce(posture, server, nonce),
        ))
    });
    (body, events)
}

/// R1 (the ticket's fail-fast, route level): a denied `gateway_invoke` with a
/// malformed nonce gets the policy refusal and counts no nonce rejection.
#[test]
fn a_denied_invoke_with_a_malformed_nonce_gets_the_policy_refusal() {
    let (body, events) = observed(SecurityPosture::Standard, "beta", &Value::Null);
    let error = &body["error"];
    assert!(error.is_object(), "the call is refused: {body}");
    assert_eq!(error["code"], json!(-32003), "policy answers first: {body}");
    assert_ne!(error["message"], json!(INVALID_REFUSAL), "{body}");
    assert_no_rejections(&events);
    // The same refusal a well-formed nonce gets: the policy's, whatever it says.
    let (policy, _) = observed(
        SecurityPosture::Standard,
        "beta",
        &json!("a-well-formed-nonce"),
    );
    assert_eq!(body, policy, "the policy refusal, not another error");
}

/// R2 (control): the same call, allowed by policy, is still refused for its
/// malformed nonce, and counted once.
#[test]
fn an_allowed_invoke_with_a_malformed_nonce_is_still_refused_and_counted() {
    let (body, events) = observed(SecurityPosture::Standard, "alpha", &Value::Null);
    assert_eq!(body["error"]["code"], json!(-32602), "{body}");
    assert_eq!(body["error"]["message"], json!(INVALID_REFUSAL), "{body}");
    assert_single_rejection(&events, "invalid");
}

/// MIK-7928 (inverse): under `hardened` the same denied call is refused for
/// its malformed nonce, before policy, and counted once.
#[test]
fn a_hardened_denied_invoke_with_a_malformed_nonce_is_refused_for_the_nonce() {
    let (body, events) = observed(SecurityPosture::Hardened, "beta", &Value::Null);
    assert_eq!(body["error"]["code"], json!(-32602), "{body}");
    assert_eq!(body["error"]["message"], json!(INVALID_REFUSAL), "{body}");
    assert_single_rejection(&events, "invalid");
}
