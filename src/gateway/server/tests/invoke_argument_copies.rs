// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 (family perf-per-call): how many times one HTTP `gateway_invoke`
//! deep-copies its arguments.
//!
//! Measured through the whole HTTP stack in-process (`create_router` →
//! `oneshot`), on one thread, in an isolated child (`isolate`), with
//! `alloc_meter`. The argument is one large string, so its heap size tracks its
//! length. The row calibrates its own unit: one explicit `arguments.clone()` of
//! the same value, at each size, under the same meter. The copy count is
//! (dispatch bytes, large − small) / (clone bytes, large − small), so fixed
//! per-call costs cancel and the count does not depend on how a `Value` lays
//! out its heap.
//!
//! Parsing the request body builds the arguments once; that is not a copy of
//! them and is subtracted. The bound is the design's: the hot path makes at
//! most two (one owned working value, one outgoing).

use std::sync::Arc;

use serde_json::{Value, json};
use tower::ServiceExt;

use super::alloc_meter::{measure, measure_async};
use super::signing_nonce_allocations_support::{isolate, runtime};
use crate::gateway::router::{AppState, create_router};

const LARGE: usize = 1024 * 1024;
const SMALL: usize = 1024;
/// Copies the hot path may make beyond the body parse (MIK-8014 design r5).
const MAX_COPIES: f64 = 2.0;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

fn arguments(size: usize) -> Value {
    json!({ "blob": "x".repeat(size) })
}

/// The fixture's `demo` backend, with `search` listed so the invoke reaches
/// the backend instead of being refused as unknown.
async fn state() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = crate::gateway::router::tests::direct_route_state_with_identity(
        crate::config::AgentIdentityConfig::default(),
    )
    .await;
    let backend = state.backends.get("demo").expect("fixture backend");
    backend.remember_listed_tools(
        None,
        false,
        &[json!({
            "name": "search",
            "description": "probe",
            "inputSchema": {
                "type": "object",
                "properties": {"blob": {"type": "string"}, "n": {"type": "number"}}
            }
        })],
    );
    (state, store)
}

fn request(size: usize) -> axum::http::Request<axum::body::Body> {
    let body = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "demo", "tool": "search", "arguments": arguments(size),
        }},
    })
    .to_string();
    axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .expect("request")
}

/// Bytes one dispatch allocates; everything is built before the scope opens.
async fn dispatch_bytes(state: &Arc<AppState>, size: usize) -> u64 {
    let (router, request) = (create_router(Arc::clone(state)), request(size));
    let (response, measured) = measure_async(|| router.oneshot(request)).await;
    let response = response.expect("router");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&body);
    // A refusal is an HTTP 200 carrying isError: the copies under test would
    // never have run.
    assert!(
        status.is_success() && !body.contains("\"isError\":true"),
        "the invoke must reach the backend: {status} {body}"
    );
    measured.bytes
}

fn clone_bytes(size: usize) -> u64 {
    let value = arguments(size);
    let (copy, measured) = measure(|| value.clone());
    drop(copy);
    measured.bytes
}

#[test]
fn one_invoke_copies_its_arguments_at_most_twice() {
    if isolate(&test_path("one_invoke_copies_its_arguments_at_most_twice")) {
        return;
    }
    runtime().block_on(async {
        let (state, _store) = state().await;
        // Warm both sizes once so lazily built state is billed to neither.
        dispatch_bytes(&state, SMALL).await;
        dispatch_bytes(&state, LARGE).await;
        let dispatch =
            dispatch_bytes(&state, LARGE).await as f64 - dispatch_bytes(&state, SMALL).await as f64;
        let unit = clone_bytes(LARGE) as f64 - clone_bytes(SMALL) as f64;
        // Positive control: the meter sees a deep copy at about its size.
        assert!(
            unit >= (LARGE - SMALL) as f64,
            "one explicit clone of a {LARGE} B argument measured {unit} B: the meter is blind"
        );
        // The body parse builds the arguments once; it is not a copy of them.
        let copies = dispatch / unit - 1.0;
        assert!(
            copies <= MAX_COPIES + 0.25,
            "one HTTP gateway_invoke deep-copied its arguments {copies:.2} times \
             (dispatch {dispatch} B over one clone {unit} B, less the body parse); \
             the bound is {MAX_COPIES} (MIK-8014)"
        );
    });
}

/// A backend that records the `arguments` each `tools/call` carries.
struct Capture(std::sync::Mutex<Vec<Value>>);

#[async_trait::async_trait]
impl crate::transport::Transport for Capture {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            let sent = params.and_then(|p| p.get("arguments").cloned());
            self.0
                .lock()
                .expect("capture")
                .push(sent.unwrap_or(Value::Null));
        }
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            json!({"content": []}),
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

/// MIK-8014, time of check vs time of use: admission now judges the request's
/// arguments by borrow and the invoke parses its own working copy, so the
/// value dispatched must be exactly the one in the request (with the gateway's
/// own `_full`/`_claim` controls removed), in every argument form.
#[test]
fn the_dispatched_arguments_are_the_admitted_ones() {
    runtime().block_on(async {
        let (state, _store) = state().await;
        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        state
            .backends
            .get("demo")
            .expect("fixture backend")
            .set_transport_for_test(Arc::clone(&capture) as Arc<dyn crate::transport::Transport>);
        let cases = [
            (json!({"blob": "v", "n": 1}), json!({"blob": "v", "n": 1})),
            (json!("{\"blob\":\"v\"}"), json!({"blob": "v"})),
            (
                json!({"blob": "v", "_full": true, "_claim": "c"}),
                json!({"blob": "v"}),
            ),
        ];
        for (sent, expected) in cases {
            let body = json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": "gateway_invoke", "arguments": {
                    "server": "demo", "tool": "search", "arguments": sent,
                }},
            })
            .to_string();
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .expect("request");
            let response = create_router(Arc::clone(&state))
                .oneshot(request)
                .await
                .expect("router");
            let status = response.status();
            let text = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let text = String::from_utf8_lossy(&text);
            assert!(
                status.is_success() && !text.contains("\"isError\":true"),
                "{status}: {text}"
            );
            let dispatched = capture.0.lock().expect("capture").pop();
            assert!(
                dispatched.is_some(),
                "nothing reached the backend; answer: {text}"
            );
            assert_eq!(dispatched, Some(expected), "sent {sent}");
        }
    });
}
