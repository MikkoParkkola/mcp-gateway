// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `events/lease` on the direct route is answered by the gateway itself: with
//! no events hub it is method-not-found, and the hub's refusals come back as
//! JSON-RPC errors, their data included. The backend never sees the request.

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

/// POST `events/lease` with `params` and a passthrough token to `/mcp/demo`,
/// with an events hub when `hub` is set; the status, the JSON body and how
/// many requests reached the backend.
async fn lease(params: Value, hub: bool) -> (StatusCode, Value, usize) {
    let reached = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(&reached))));
    let (state, store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    if hub {
        let hub = crate::events::EventsHub::open(
            &crate::config::EventsConfig::default(),
            &store.path().join("events"),
        )
        .expect("the events hub opens");
        state.meta_mcp.set_events(hub);
    }
    assert!(state.backends.register(backend));
    let request = Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .header(super::super::PASSTHROUGH_HEADER, "Bearer a.b.c")
        .body(Body::from(
            json!({"jsonrpc": "2.0", "id": 5, "method": "events/lease", "params": params})
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
async fn a_lease_with_no_events_hub_is_method_not_found() {
    let (status, body, reached) = lease(json!({"subscription": "h"}), false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["error"]["code"], -32601, "{body}");
    assert_eq!(reached, 0, "never forwarded");
}

/// A refusal with data keeps it (the offending field, never its value); one
/// without is a bare error. Neither reaches the backend.
#[tokio::test]
async fn the_hubs_refusals_answer_the_caller_and_never_forward() {
    let (status, body, reached) = lease(json!({}), true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
    assert_eq!(body["error"]["data"]["field"], "subscription", "{body}");
    assert_eq!(reached, 0, "never forwarded");
    let (_, body, reached) = lease(json!({"subscription": "not-a-handle"}), true).await;
    assert_eq!(body["error"]["code"], -32012, "{body}");
    assert!(body["error"].get("data").is_none(), "{body}");
    assert_eq!(reached, 0, "never forwarded");
}
