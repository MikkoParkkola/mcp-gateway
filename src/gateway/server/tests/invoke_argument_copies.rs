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
pub(super) async fn state() -> (Arc<AppState>, tempfile::TempDir) {
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
        status.is_success() && body.contains("\"result\"") && !body.contains("\"isError\":true"),
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

/// A byte count as `f64`, exactly: every count here is a few megabytes.
fn exact<T: TryInto<u32>>(bytes: T) -> f64
where
    T::Error: std::fmt::Debug,
{
    f64::from(bytes.try_into().expect("a byte count under 4 GiB"))
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
            exact(dispatch_bytes(&state, LARGE).await) - exact(dispatch_bytes(&state, SMALL).await);
        let unit = exact(clone_bytes(LARGE)) - exact(clone_bytes(SMALL));
        // Positive control: the meter sees a deep copy at about its size.
        assert!(
            unit >= exact(LARGE - SMALL),
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
        // The last case carries a client `_meta` beside `arguments`: the one
        // branch where the router copies the wrapper to merge it in.
        let cases = [
            (
                json!({"blob": "v", "n": 1}),
                json!({"blob": "v", "n": 1}),
                None,
            ),
            (json!("{\"blob\":\"v\"}"), json!({"blob": "v"}), None),
            (
                json!({"blob": "v", "_full": true, "_claim": "c"}),
                json!({"blob": "v"}),
                None,
            ),
            (
                json!({"blob": "v"}),
                json!({"blob": "v"}),
                Some(json!({"progressToken": "p"})),
            ),
        ];
        for (sent, expected, meta) in cases {
            let mut body = json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {"name": "gateway_invoke", "arguments": {
                    "server": "demo", "tool": "search", "arguments": sent,
                }},
            });
            if let Some(meta) = meta {
                body["params"]["_meta"] = meta;
            }
            let body = body.to_string();
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

/// A backend that answers at once, counts its `tools/call`s and never
/// touches what it is sent.
struct Answer(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl crate::transport::Transport for Answer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/call" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

/// The stdio dispatcher over one in-process backend, `bench`, listing `search`.
struct StdioStack {
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    policy: Arc<crate::security::ToolPolicy>,
    mtls: Arc<crate::mtls::MtlsPolicy>,
    answer: Arc<Answer>,
}

fn stdio_stack() -> StdioStack {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let mut failsafe = crate::config::FailsafeConfig::default();
    failsafe.rate_limit.enabled = false;
    let backend = Arc::new(crate::backend::Backend::new(
        "bench",
        crate::config::BackendConfig::default(),
        &failsafe,
        std::time::Duration::from_secs(60),
    ));
    let answer = Arc::new(Answer(std::sync::atomic::AtomicUsize::new(0)));
    backend.set_transport_for_test(Arc::clone(&answer) as Arc<dyn crate::transport::Transport>);
    backend.remember_listed_tools(
        None,
        false,
        &[json!({
            "name": "search",
            "description": "probe",
            "inputSchema": {"type": "object", "properties": {"blob": {"type": "string"}}}
        })],
    );
    assert!(registry.register(backend));
    StdioStack {
        meta: Arc::new(crate::gateway::meta_mcp::MetaMcp::new(registry)),
        policy: Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig::default(),
        )),
        mtls: Arc::new(crate::mtls::MtlsPolicy::from_config(
            &crate::mtls::MtlsConfig::default(),
        )),
        answer,
    }
}

/// Bytes one stdio dispatch allocates; the request is built before the scope.
/// The dispatch must answer with a result and reach the backend exactly once.
async fn stdio_dispatch_bytes(stack: &StdioStack, size: usize) -> u64 {
    let request = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "bench", "tool": "search", "arguments": arguments(size),
        }},
    });
    let telemetry = super::super::StdioTelemetry::default();
    let before = stack.answer.0.load(std::sync::atomic::Ordering::Relaxed);
    let (response, measured) = measure_async(|| {
        super::super::Gateway::dispatch_single_with_sink(
            &stack.meta,
            &stack.policy,
            &stack.mtls,
            request,
            super::super::StdioClient {
                session_id: "copies",
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: crate::protocol::meta::Declared::NONE,
                tasks: None,
                modern: false,
                sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
            },
            &telemetry,
        )
    })
    .await;
    let dispatched = stack.answer.0.load(std::sync::atomic::Ordering::Relaxed) - before;
    let text = response.expect("a tools/call is answered").to_string();
    assert!(
        dispatched == 1 && text.contains("\"result\"") && !text.contains("\"isError\":true"),
        "the stdio invoke must reach the backend once ({dispatched}): {text}"
    );
    measured.bytes
}

/// The stdio half of site 1: the stdio path hands the request's arguments
/// down borrowed too. No body parse here: the request is already a value.
#[test]
fn one_stdio_invoke_copies_its_arguments_at_most_twice() {
    if isolate(&test_path(
        "one_stdio_invoke_copies_its_arguments_at_most_twice",
    )) {
        return;
    }
    runtime().block_on(async {
        let stack = stdio_stack();
        stdio_dispatch_bytes(&stack, SMALL).await;
        stdio_dispatch_bytes(&stack, LARGE).await;
        let dispatch = exact(stdio_dispatch_bytes(&stack, LARGE).await)
            - exact(stdio_dispatch_bytes(&stack, SMALL).await);
        let unit = exact(clone_bytes(LARGE)) - exact(clone_bytes(SMALL));
        let copies = dispatch / unit;
        assert!(
            copies <= MAX_COPIES + 0.25,
            "one stdio gateway_invoke deep-copied its arguments {copies:.2} times \
             (dispatch {dispatch} B over one clone {unit} B); the bound is {MAX_COPIES} (MIK-8014)"
        );
    });
}
