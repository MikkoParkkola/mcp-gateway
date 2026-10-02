// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's `tools/call` refusals that run before any dispatch: a
//! missing or malformed tool name, and an argument the sanitizer rejects.
//! Each leaves the backend untouched.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::router::create_router;
use crate::gateway::router::tests::{scoped_auth_config, test_router_app_state_with_auth};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// Counts every request that reaches the backend.
struct Counting(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Transport for Counting {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"content": [], "isError": false}),
        ))
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

/// POST `params` as a `tools/call` to `/mcp/demo`; returns the status, the
/// JSON body and how many requests reached the backend.
async fn call(params: Value) -> (StatusCode, Value, usize) {
    let reached = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(&reached))));
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    assert!(state.backends.register(backend));
    let request = Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body, reached.load(Ordering::SeqCst))
}

#[tokio::test]
async fn a_call_without_a_tool_name_is_a_bad_request() {
    for params in [json!({}), json!({"name": ""}), json!({"name": 7})] {
        let (status, body, reached) = call(params.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{params}: {body}");
        assert_eq!(body["error"]["code"], -32602, "{params}: {body}");
        assert_eq!(reached, 0, "{params}");
    }
}

#[tokio::test]
async fn a_malformed_tool_name_is_refused_before_authorization() {
    let (status, body, reached) = call(json!({"name": "bad name/../x"})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(reached, 0);
}

#[tokio::test]
async fn an_argument_the_sanitizer_rejects_never_reaches_the_backend() {
    let (status, body, reached) =
        call(json!({"name": "allowed_tool", "arguments": {"q": "a\u{0}b"}})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], -32600, "{body}");
    assert_eq!(reached, 0, "{body}");
}
