// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.10: judging a cached tool copies none of it.
//!
//! The catalogue verdict reads one held entry to decide whether a name is
//! offered. It used to deep-copy the whole `Tool`, input schema included, for
//! that one read: twice per HTTP `gateway_invoke` (the route stage and the
//! meta gate each judge the target). Measured like `invoke_argument_copies`,
//! with the size in the listed tool's schema instead of the arguments: two
//! states that differ only in a SMALL or LARGE description inside the schema,
//! the same small call to each. The unit is one `get_cached_tool_for` clone of
//! that descriptor at each size, so fixed per-call costs cancel.

use std::sync::Arc;

use serde_json::json;
use tower::ServiceExt;

use super::alloc_meter::{measure, measure_async};
use super::signing_nonce_allocations_support::{isolate, runtime};
use crate::backend::CatalogueVerdict;
use crate::gateway::router::{AppState, create_router};

const LARGE: usize = 256 * 1024;
const SMALL: usize = 256;
/// Below one copy, with room for allocator rounding.
const MAX_COPIES: f64 = 0.25;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// The fixture's `demo` backend with `search` listed, its schema padded.
async fn state(pad: usize) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let (state, store) = crate::gateway::router::tests::direct_route_state_with_identity(
        crate::config::AgentIdentityConfig::default(),
    )
    .await;
    state
        .backends
        .get("demo")
        .expect("fixture backend")
        .remember_listed_tools(
            None,
            false,
            &[json!({
                "name": "search",
                "description": "probe",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "blob": {"type": "string", "description": "x".repeat(pad)},
                        "n": {"type": "number"}
                    }
                }
            })],
        );
    (state, store)
}

fn invoke() -> axum::http::Request<axum::body::Body> {
    let body = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "demo", "tool": "search", "arguments": {"blob": "v"},
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

/// Bytes one dispatch allocates. The answer is checked after the scope closes:
/// a refusal would never have judged the target.
async fn dispatch_bytes(state: &Arc<AppState>) -> u64 {
    let (router, request) = (create_router(Arc::clone(state)), invoke());
    let (response, measured) = measure_async(|| router.oneshot(request)).await;
    let response = response.expect("router");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&body);
    assert!(
        status.is_success() && body.contains("\"result\"") && !body.contains("\"isError\":true"),
        "the invoke must reach the backend: {status} {body}"
    );
    measured.bytes
}

/// One deep copy of the padded descriptor: the unit a copy is counted in.
fn clone_bytes(state: &Arc<AppState>) -> u64 {
    let backend = state.backends.get("demo").expect("fixture backend");
    let (copy, measured) = measure(|| backend.get_cached_tool_for(None, "search"));
    assert!(copy.is_some(), "the padded tool is listed");
    measured.bytes
}

/// A byte count as `f64`, exactly: every count here is under a few megabytes.
fn exact(bytes: u64) -> f64 {
    f64::from(u32::try_from(bytes).expect("a byte count under 4 GiB"))
}

fn unit(small: &Arc<AppState>, large: &Arc<AppState>) -> f64 {
    let unit = exact(clone_bytes(large)) - exact(clone_bytes(small));
    // Positive control: the meter sees one copy at about the pad's size.
    assert!(
        unit >= exact(u64::try_from(LARGE - SMALL).expect("small")),
        "one descriptor clone measured {unit} B for a {LARGE} B pad: the meter is blind"
    );
    unit
}

/// A warm HTTP `gateway_invoke` copies its target's listed descriptor zero
/// times. Mutant: `catalogue_verdict_inner` judging a `get_cached_tool_for`
/// clone again (2 copies, one per judgement).
#[test]
fn a_warm_invoke_copies_no_descriptor() {
    if isolate(&test_path("a_warm_invoke_copies_no_descriptor")) {
        return;
    }
    runtime().block_on(async {
        let (small, _s) = state(SMALL).await;
        let (large, _l) = state(LARGE).await;
        // Warm both so lazily built state is billed to neither.
        for _ in 0..2 {
            dispatch_bytes(&small).await;
            dispatch_bytes(&large).await;
        }
        let dispatch = exact(dispatch_bytes(&large).await) - exact(dispatch_bytes(&small).await);
        let copies = dispatch / unit(&small, &large);
        assert!(
            copies < MAX_COPIES,
            "one warm gateway_invoke deep-copied its target's descriptor {copies:.2} times \
             (dispatch {dispatch} B); judging it needs none (MIK-8014 PERF.10)"
        );
    });
}

/// The `off`-mode twin, `held_verdict`, judges the held entry without a copy.
/// Mutant: `held_verdict` judging a `get_cached_tool_for` clone again.
#[test]
fn held_verdict_copies_no_descriptor() {
    if isolate(&test_path("held_verdict_copies_no_descriptor")) {
        return;
    }
    runtime().block_on(async {
        let (small, _s) = state(SMALL).await;
        let (large, _l) = state(LARGE).await;
        let verdict_bytes = |state: &Arc<AppState>| {
            let backend = state.backends.get("demo").expect("fixture backend");
            let (verdict, measured) = measure(|| backend.held_verdict(None, "search"));
            assert_eq!(
                verdict,
                CatalogueVerdict::Offers,
                "the padded tool is offered"
            );
            measured.bytes
        };
        let held = exact(verdict_bytes(&large)) - exact(verdict_bytes(&small));
        let copies = held / unit(&small, &large);
        assert!(
            copies < MAX_COPIES,
            "held_verdict deep-copied the descriptor {copies:.2} times (MIK-8014 PERF.10)"
        );
    });
}
