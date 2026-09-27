// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11-b / A11-g (T8): a deterministic refusal status reaches the caller as a
//! typed `Error::Http`, and is sent exactly once.
//!
//! The body is plain text on purpose: a status-carried JSON-RPC error takes
//! the `peer_refusal` path first, and this row pins the status arm below it.
//! The body says "401" for every status, so only the status can decide.

use std::sync::atomic::Ordering;

use super::*;

async fn refused_once(status: axum::http::StatusCode) {
    let (addr, hits, server) = spawn_fixed_response_server(status, "401 invalid_token").await;
    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/call")
        .await
        .expect_err("a refusal status must not report success");

    match &err {
        Error::Http(inner) => assert_eq!(
            inner.status().map(|s| s.as_u16()),
            Some(status.as_u16()),
            "the typed error must carry the status"
        ),
        other => panic!("{status} must be a typed Error::Http, got: {other:?}"),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "{status} is a deterministic refusal: retrying repeats it"
    );
    server.abort();
}

#[tokio::test]
async fn unmanaged_backend_401_is_typed_and_not_retried() {
    refused_once(axum::http::StatusCode::UNAUTHORIZED).await;
}

#[tokio::test]
async fn backend_403_is_typed_and_not_retried() {
    refused_once(axum::http::StatusCode::FORBIDDEN).await;
}

/// Row 16f - the retry boundary of the same branch. A peer under load can echo
/// the request id in a JSON-RPC error body while its status says "ask again".
/// Reading that as the peer's considered answer would take the retry away from
/// exactly the case the retry exists for, so a transient status keeps the
/// opaque fault the retry classifiers already understand.
#[tokio::test]
async fn row_16f_a_transient_status_carrying_a_json_rpc_error_is_still_retried() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32000,"message":"rate limited"}}"#,
    )
    .await;

    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));

    let err = request_through_retry(&transport, "tools/list")
        .await
        .expect_err("a 429 must not report success");

    match &err {
        Error::JsonRpcRetryable { code, status, .. } => {
            assert_eq!(*code, -32000, "the peer's own code must survive the retry");
            assert_eq!(*status, 429, "the carriage is what made it retryable");
        }
        other => panic!("a transient status must keep both facts, got: {other:?}"),
    }
    assert_eq!(
        hits.load(Ordering::Relaxed),
        3,
        "a transient status stays retryable; a JSON-RPC body must not make it terminal"
    );

    server.abort();
}
