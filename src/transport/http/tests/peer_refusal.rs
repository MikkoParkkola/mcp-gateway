// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 W1 (`peer_refusal`, critical d): a peer's JSON-RPC error body is
//! surfaced only when its id answers this request; a stray or replayed
//! reply is withheld.

use super::*;
use crate::protocol::RequestId;

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
    let Some(Error::JsonRpc { code, message, .. }) = refusal else {
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

/// The status-path body as each non-retry status carries it.
fn refused_on(status: reqwest::StatusCode) -> Error {
    peer_refusal(&error_body(7), &RequestId::Number(7), status)
        .unwrap_or_else(|| panic!("premise: a {status} body answering this request is surfaced"))
}

/// MIK-9091.BEO.1: a peer's own refusal on a non-retry status is the
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

/// MIK-9091.BEO.1 control: a 500 already keeps the peer's code as a
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
