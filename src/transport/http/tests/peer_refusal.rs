// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 W1 (`peer_refusal`, critical d): a peer's JSON-RPC error body is
//! surfaced only when its id answers this request; a stray or replayed
//! reply is withheld.

use super::*;
use crate::protocol::RequestId;
use std::sync::atomic::Ordering;

fn error_body(id: i64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32001, "message": "peer refused"}
    })
    .to_string()
}

#[test]
fn a_peer_error_answering_this_request_is_surfaced() {
    let refusal = peer_refusal(
        &error_body(7),
        &RequestId::Number(7),
        reqwest::StatusCode::FORBIDDEN,
    );
    let Some(Error::BackendJsonRpc { code, message, .. }) = refusal else {
        panic!("the peer's error was not surfaced: {refusal:?}");
    };
    assert_eq!(code, -32001);
    assert_eq!(message, "peer refused");
}

#[test]
fn a_peer_error_for_another_request_is_withheld() {
    let refusal = peer_refusal(
        &error_body(8),
        &RequestId::Number(7),
        reqwest::StatusCode::FORBIDDEN,
    );
    assert!(
        refusal.is_none(),
        "a reply to another request was attributed: {refusal:?}"
    );
}

/// A backend's 403 is its own answer, after the request reached it: with a
/// JSON-RPC body carrying the gateway's own denial code (-32003), and with no
/// body, it is never the gateway's denial, so it never reads as never sent
/// and never frees the caller's key.
#[test]
fn a_backends_403_is_never_the_gateways_denial() {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "error": {"code": -32003, "message": "not permitted"}
    })
    .to_string();
    let peer = peer_refusal(&body, &RequestId::Number(7), reqwest::StatusCode::FORBIDDEN)
        .expect("the peer's error is surfaced");
    assert!(
        matches!(peer, Error::BackendJsonRpc { code: -32003, .. }),
        "{peer:?}"
    );
    assert!(!peer.is_pre_dispatch(), "{peer:?}");
    let bare = crate::security::http_diagnostics::safe_http_status_error(
        reqwest::StatusCode::FORBIDDEN,
        "",
    );
    assert!(
        !matches!(bare, Error::Forbidden { .. } | Error::GatewayRefused { .. }),
        "{bare:?}"
    );
    assert!(!bare.is_pre_dispatch(), "{bare:?}");
}

/// The same over real HTTP: a backend's 403 reached the backend. The
/// transport answers a 401/403 with its typed status whatever the body says
/// (so a managed account's refresh sees the status), so both a body carrying
/// the gateway's own denial code and no body reach the caller as `Http` 403:
/// never the gateway's denial, never read as never sent. This row cannot see
/// `peer_refusal`, whose result the transport discards for a 403; the row
/// above covers it.
#[tokio::test]
async fn a_backends_403_over_http_is_never_the_gateways_denial() {
    let (addr, hits, server) = spawn_fixed_response_server(
        axum::http::StatusCode::FORBIDDEN,
        r#"{"jsonrpc":"2.0","id":{id},"error":{"code":-32003,"message":"not permitted"}}"#,
    )
    .await;
    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    let error = transport
        .request("tools/call", Some(serde_json::json!({"name": "write"})))
        .await
        .expect_err("the backend answered 403");
    assert!(
        matches!(&error, Error::Http(e) if e.status() == Some(reqwest::StatusCode::FORBIDDEN)),
        "a -32003 body: {error:?}"
    );
    assert!(!error.is_pre_dispatch(), "{error:?}");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "premise: it reached the backend"
    );
    server.abort();

    let (addr, hits, server) =
        spawn_fixed_response_server(axum::http::StatusCode::FORBIDDEN, "").await;
    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    let error = transport
        .request("tools/call", Some(serde_json::json!({"name": "write"})))
        .await
        .expect_err("the backend answered 403");
    assert!(
        matches!(&error, Error::Http(e) if e.status() == Some(reqwest::StatusCode::FORBIDDEN)),
        "no body: {error:?}"
    );
    assert!(!error.is_pre_dispatch(), "{error:?}");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "premise: it reached the backend"
    );
    server.abort();
}

/// The status-path body as each non-retry status carries it.
fn refused_on(status: reqwest::StatusCode) -> Error {
    peer_refusal(&error_body(7), &RequestId::Number(7), status)
        .unwrap_or_else(|| panic!("premise: a {status} body answering this request is surfaced"))
}

/// A peer's own refusal on a non-retry status is the
/// backend's answer, whatever its code, so it is counted as the backend's.
#[test]
fn a_peers_refusal_on_a_non_retry_status_is_the_backends() {
    for status in [
        reqwest::StatusCode::BAD_REQUEST,
        reqwest::StatusCode::NOT_FOUND,
        reqwest::StatusCode::CONFLICT,
    ] {
        let refusal = refused_on(status);
        assert_eq!(refusal.to_rpc_code(), -32001, "{status}: {refusal:?}");
        assert_eq!(refusal.to_string(), "JSON-RPC error -32001: peer refused");
        assert_eq!(
            refusal.origin(),
            crate::protocol::Origin::Backend,
            "{status}: a peer's refusal read as the gateway's: {refusal:?}"
        );
    }
}

/// Control: a 500 already keeps the peer's code as a
/// retryable refusal, the backend's.
#[test]
fn a_peers_refusal_on_a_500_stays_the_backends() {
    let refusal = refused_on(reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        matches!(refusal, Error::JsonRpcRetryable { .. }),
        "{refusal:?}"
    );
    assert_eq!(refusal.origin(), crate::protocol::Origin::Backend);
}
