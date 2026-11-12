// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusals the meta route and its body reader give: a
//! malformed chain nonce on `/mcp`, and a body that fails to read for a
//! reason other than its size.

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::json;

use super::direct_guards_fixture::{Answer, fixture, send};
use super::helpers::read_body;
use crate::protocol::mrtr::CHAIN_NONCE_META;

#[tokio::test]
async fn a_malformed_chain_nonce_on_the_meta_route_is_refused() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let params = json!({
        "name": "gateway_search_tools",
        "arguments": {"query": "read"},
        "_meta": { CHAIN_NONCE_META: 5 },
    });
    let (status, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32602, "{body}");
}

#[tokio::test]
async fn a_body_that_fails_to_read_is_a_parse_error() {
    let failing = futures::stream::iter([Err::<Vec<u8>, std::io::Error>(std::io::Error::other(
        "connection reset",
    ))]);
    let request = axum::extract::Request::new(Body::from_stream(failing));
    let Err(super::helpers::RpcHttp { status, body, .. }) = read_body(request).await else {
        panic!("a failing body must not read");
    };
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.0["error"]["code"], -32700, "{}", body.0);
}

/// The gateway does not check meta-tool arguments against the advertised
/// schema, so a `limit` outside 1 to 25 reaches the handler, which clamps it,
/// rather than being refused on the way in. One capability matches "read",
/// so a 0 raised to 1 shows as exactly one match, where 0 gave none.
#[tokio::test]
async fn an_out_of_range_search_limit_is_answered_not_refused() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let caps = crate::test_dir_keep::kept_tempdir();
    std::fs::write(
        caps.path().join("read_limit_probe.yaml"),
        "name: read_limit_probe\ndescription: read a limit probe\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.invalid\n      path: /probe\n",
    )
    .unwrap();
    let backend = std::sync::Arc::new(crate::capability::CapabilityBackend::new(
        "limit_probe",
        std::sync::Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let loaded = backend
        .load_from_directory(caps.path().to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(loaded, 1, "the probe capability must load");
    fx.state.meta_mcp.set_capabilities(backend);
    for (limit, allowed) in [(0, 1..=1), (1000, 1..=25)] {
        let params = json!({
            "name": "gateway_search_tools",
            "arguments": {"query": "read", "limit": limit},
        });
        let (status, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
        assert_eq!(status, StatusCode::OK, "limit {limit}: {body}");
        assert!(body["error"].is_null(), "limit {limit}: {body}");
        assert_ne!(
            body["result"]["isError"],
            json!(true),
            "limit {limit}: {body}"
        );
        let matches = body["result"]["structuredContent"]["matches"]
            .as_array()
            .unwrap_or_else(|| panic!("limit {limit}: no matches array: {body}"))
            .len();
        assert!(
            allowed.contains(&matches),
            "limit {limit}: {matches} matches: {body}"
        );
    }
}
