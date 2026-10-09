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

/// One request against a peer that answers every POST with `status` and
/// `body`, through the production retry wrapper; the error and the hit count.
async fn refusal_of(status: axum::http::StatusCode, body: &'static str) -> (Error, u32) {
    let (addr, hits, server) = spawn_fixed_response_server(status, body).await;
    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    let err = request_through_retry(&transport, "tools/call")
        .await
        .expect_err("a refusal status must not report success");
    server.abort();
    (err, hits.load(Ordering::Relaxed))
}

fn assert_typed(err: &Error, status: u16) {
    match err {
        Error::Http(inner) => assert_eq!(inner.status().map(|s| s.as_u16()), Some(status)),
        other => panic!("{status} must be typed by its status, got: {other:?}"),
    }
}

/// MIK-7717 (the ticket's fail-fast): a credential refusal is typed by its
/// status whatever its body. A JSON-RPC error answering this very request
/// must not hide the 401 from the managed-account refresh.
#[tokio::test]
async fn a_401_carrying_a_json_rpc_error_is_typed_by_its_status() {
    let (err, hits) = refusal_of(
        axum::http::StatusCode::UNAUTHORIZED,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32001,"message":"unauthorized"}}"#,
    )
    .await;
    assert_typed(&err, 401);
    assert_eq!(hits, 1, "a deterministic refusal is sent once");
}

#[tokio::test]
async fn a_403_carrying_a_json_rpc_error_is_typed_by_its_status() {
    let (err, hits) = refusal_of(
        axum::http::StatusCode::FORBIDDEN,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32001,"message":"forbidden"}}"#,
    )
    .await;
    assert_typed(&err, 403);
    assert_eq!(hits, 1, "a deterministic refusal is sent once");
}

/// MIK-7717: a parsed refusal that is not an expiry is decided by its status,
/// not by a body-text scan that finds "session expired" in its `data`.
#[tokio::test]
async fn expiry_words_in_a_refusals_data_do_not_override_its_status() {
    let (err, _) = refusal_of(
        axum::http::StatusCode::UNAUTHORIZED,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32001,"message":"unauthorized","data":"session expired"}}"#,
    )
    .await;
    assert_typed(&err, 401);
}

/// Guard: a 401 whose JSON-RPC error says the session expired keeps the
/// re-initialization path, by code and by message.
#[tokio::test]
async fn a_401_json_rpc_session_expiry_keeps_session_recovery() {
    for (body, code) in [
        (
            r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32015,"message":"Session not found"}}"#,
            -32015,
        ),
        // By code alone: a neutral message must not decide it.
        (
            r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32015,"message":"gone"}}"#,
            -32015,
        ),
        (
            r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32001,"message":"Session expired"}}"#,
            -32001,
        ),
    ] {
        let (err, _) = refusal_of(axum::http::StatusCode::UNAUTHORIZED, body).await;
        assert!(
            is_session_expired_error(&err),
            "{body} must re-initialize the session, got: {err:?}"
        );
        // The parsed refusal keeps the peer's own code.
        assert!(
            matches!(err, Error::JsonRpc { code: c, .. } if c == code),
            "{body}: {err:?}"
        );
    }
}

/// The plain-text carriage agrees with the JSON one: a 401 whose text says
/// the session expired re-initializes rather than refreshing the credential.
#[tokio::test]
async fn a_plain_401_saying_the_session_expired_keeps_session_recovery() {
    let (err, _) = refusal_of(axum::http::StatusCode::UNAUTHORIZED, "Session expired").await;
    assert!(
        is_session_expired_error(&err),
        "a plain-text expiry must re-initialize the session, got: {err:?}"
    );
}
