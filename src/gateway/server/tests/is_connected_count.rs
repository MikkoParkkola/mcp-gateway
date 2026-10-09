// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.4: how many times one warm HTTP `gateway_invoke` asks its
//! backend transport whether it is alive. The stdio transport answers with a
//! `try_lock` plus `waitpid`, so each extra check is a syscall per call.
//!
//! Counted on a test transport: the checks are made by the backend layer
//! (`lifecycle.rs`, `status.rs`), never by a transport on itself, so the
//! count does not depend on which transport answers.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use tower::ServiceExt;

use crate::gateway::router::create_router;

/// A backend that answers at once and counts liveness checks.
struct Counted {
    checks: AtomicUsize,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Counted {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            json!({"content": []}),
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

async fn invoke(state: &Arc<crate::gateway::router::AppState>) -> String {
    let body = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "demo", "tool": "search", "arguments": {"blob": "x"},
        }},
    })
    .to_string();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn a_warm_invoke_checks_its_transport_once() {
    super::signing_nonce_allocations_support::runtime().block_on(async {
        let (state, _store) = super::invoke_argument_copies::state().await;
        let counted = Arc::new(Counted {
            checks: AtomicUsize::new(0),
        });
        state
            .backends
            .get("demo")
            .expect("fixture backend")
            .set_transport_for_test(Arc::clone(&counted) as Arc<dyn crate::transport::Transport>);
        // Warm: the first call may start, list and cache.
        let first = invoke(&state).await;
        assert!(first.contains("\"result\"") && !first.contains("\"isError\":true"), "{first}");
        let before = counted.checks.load(Ordering::Relaxed);
        let text = invoke(&state).await;
        assert!(text.contains("\"result\"") && !text.contains("\"isError\":true"), "{text}");
        let checks = counted.checks.load(Ordering::Relaxed) - before;
        assert_eq!(
            checks, 1,
            "one warm gateway_invoke asked its transport is_connected {checks} times (MIK-8014 PERF.4)"
        );
    });
}
