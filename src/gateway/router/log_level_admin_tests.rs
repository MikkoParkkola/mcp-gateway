// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `logging/setLevel` on the meta route is a gateway-wide operator action.
//!
//! Its own file because `router/tests.rs` is over the 800-line ceiling and the
//! gate ratchets. The handler forwards the level to every shared backend over
//! the gateway's own credential, so one non-admin key could switch every
//! user's shared backend to `debug`. The direct route `POST /mcp/{name}`
//! forwards it to one backend, whose level is just as shared. Both routes
//! refuse non-admin callers; stdio calls the handler directly and stays open.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

/// A shared backend upstream that records every method it was asked.
struct RecordingWire {
    seen: parking_lot::Mutex<Vec<String>>,
}

impl RecordingWire {
    fn forwarded(&self, method: &str) -> bool {
        self.seen.lock().iter().any(|m| m == method)
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for RecordingWire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push(method.to_string());
        Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

const KEY: &str = "key-log-level";

/// The meta route and the direct route to the shared backend.
const META: &str = "/mcp";
const DIRECT: &str = "/mcp/shared";

/// A gateway with auth on, one key (`admin` as given, scoped to the one
/// backend) and one shared backend on a recording wire. Returns the reply to
/// `logging/setLevel {"level":"debug"}` sent to `uri`, and whether the wire
/// saw the forward.
async fn set_level_as(admin: bool, uri: &str) -> (StatusCode, Value, bool) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: KEY.to_string(),
            name: KEY.to_string(),
            rate_limit: 0,
            backends: vec!["shared".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin,
        }],
        ..Default::default()
    };
    let (state, _store) = test_router_app_state_with_auth(&auth).await;
    let wire = Arc::new(RecordingWire {
        seen: parking_lot::Mutex::new(Vec::new()),
    });
    let backend = Arc::new(Backend::new(
        "shared",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    assert!(state.backends.register(backend), "fixture registration");

    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "logging/setLevel",
                "params": { "level": "debug" }
            })
            .to_string(),
        ))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&body).unwrap();
    (status, body, wire.forwarded("logging/setLevel"))
}

#[tokio::test]
async fn a_non_admin_key_cannot_set_the_gateway_log_level() {
    let (status, body, forwarded) = set_level_as(false, META).await;

    assert_eq!(
        body["error"]["code"], -32600,
        "a non-admin key must be refused in the admin-denial shape: {body}"
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        !forwarded,
        "a non-admin key switched a shared backend's log level for every user"
    );
}

/// Positive control: without it, a gateway that forwards to nobody would pass
/// the refusal row above.
#[tokio::test]
async fn an_admin_key_still_sets_the_level_on_shared_backends() {
    let (status, body, forwarded) = set_level_as(true, META).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "admin must succeed: {body}");
    assert!(
        forwarded,
        "an admin's level never reached the shared backend"
    );
}

/// The direct route forwards to one backend, but that backend's level is
/// shared by every user of it, so a scoped key may not set it either.
#[tokio::test]
async fn a_non_admin_key_cannot_set_a_shared_backend_level_on_the_direct_route() {
    let (status, body, forwarded) = set_level_as(false, DIRECT).await;

    assert_eq!(
        body["error"]["code"], -32600,
        "a non-admin key must be refused in the admin-denial shape: {body}"
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        !forwarded,
        "a scoped non-admin key switched a shared backend's log level for every user"
    );
}

/// Positive control for the direct-route refusal above.
#[tokio::test]
async fn an_admin_key_still_sets_the_level_on_the_direct_route() {
    let (status, body, forwarded) = set_level_as(true, DIRECT).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "admin must succeed: {body}");
    assert!(forwarded, "an admin's level never reached the backend");
}
