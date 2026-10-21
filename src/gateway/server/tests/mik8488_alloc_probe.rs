// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488 PR-B1: the allocation probe for the stage refactor.

use std::sync::Arc;

use serde_json::json;
use tower::ServiceExt;

use super::alloc_meter::measure_async;
use crate::gateway::router::create_router;

const SMALL: usize = 1024;
const LARGE: usize = 1024 * 1024;

fn request(size: usize) -> axum::http::Request<axum::body::Body> {
    let body = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "demo", "tool": "search", "arguments": {"blob": "x".repeat(size)},
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

async fn dispatch_once(state: &Arc<crate::gateway::router::AppState>, size: usize) {
    let response = create_router(Arc::clone(state))
        .oneshot(request(size))
        .await
        .expect("router");
    let _body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
}

/// The baseline measurement, run on each PR against its own parent.
/// Procedure: `cargo test --lib gateway::server::signing_allocation_tests::mik8488_alloc_probe::mik8488_allocation_probe -- --ignored --exact --nocapture --test-threads=1`.
#[test]
#[ignore]
fn mik8488_allocation_probe() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let (state, _store) = super::invoke_argument_copies::state().await;
            for size in [SMALL, LARGE] {
                dispatch_once(&state, size).await;
                dispatch_once(&state, size).await;
            }
            for (label, size) in [("small", SMALL), ("large", LARGE)] {
                for round in 0..3 {
                    let router = create_router(Arc::clone(&state));
                    let req = request(size);
                    let (response, measured) = measure_async(|| router.oneshot(req)).await;
                    let response = response.expect("router");
                    let _body = axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .expect("body");
                    println!(
                        "MIK8488 {label} round {round}: bytes={} calls={} largest={} large={}",
                        measured.bytes, measured.calls, measured.largest, measured.large
                    );
                }
            }
        });
}
