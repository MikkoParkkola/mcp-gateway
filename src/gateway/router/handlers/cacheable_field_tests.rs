// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The cacheable-field builder, driven directly.

use super::modern_response::{CACHEABLE_METHODS, build_modern_response};
use crate::protocol::{JsonRpcResponse, RequestId};
use axum::http::StatusCode;

/// CACHE.1a and CACHE.1b claim both fields on **all five** methods. The
/// HTTP acceptance test can only reach four of them -- `resources/read`
/// needs a backend serving a URI, and an error result carries nothing to
/// decorate. Driving the builder directly covers the fifth, and iterating
/// the constant rather than a hand-copied list means a sixth method cannot
/// be added without this test demanding its fields too.
#[tokio::test]
async fn every_cacheable_method_gets_both_fields() {
    // "All five" is half the claim; iterating the constant alone would
    // still pass if a method were dropped from it.
    assert_eq!(
        CACHEABLE_METHODS.len(),
        6,
        "five cacheable methods and discovery: {CACHEABLE_METHODS:?}"
    );
    for method in CACHEABLE_METHODS {
        let response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
        let built = build_modern_response(response, StatusCode::OK, method);
        let bytes = axum::body::to_bytes(built.into_body(), usize::MAX)
            .await
            .expect("the builder produces a complete in-memory body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("the body is JSON-RPC");

        assert!(
            body["result"]["ttlMs"].as_u64().is_some_and(|ttl| ttl > 0),
            "{method} must carry a positive ttlMs: {body}"
        );
        assert!(
            body["result"]["cacheScope"].as_str().is_some(),
            "{method} must carry a cacheScope: {body}"
        );
    }
}

/// The mirror: a method outside the list gets neither field. Without this,
/// a builder that decorated everything would pass the case above.
#[tokio::test]
async fn a_non_cacheable_method_gets_neither_field() {
    let response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
    let built = build_modern_response(response, StatusCode::OK, "tools/call");
    let bytes = axum::body::to_bytes(built.into_body(), usize::MAX)
        .await
        .expect("the builder produces a complete in-memory body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("the body is JSON-RPC");

    assert!(body["result"].get("ttlMs").is_none(), "{body}");
    assert!(body["result"].get("cacheScope").is_none(), "{body}");
}
