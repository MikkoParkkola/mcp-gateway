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
    let Err((status, body)) = read_body(request).await else {
        panic!("a failing body must not read");
    };
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.0["error"]["code"], -32700, "{}", body.0);
}
