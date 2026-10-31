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
        matches!(peer, Error::JsonRpc { code: -32003, .. }),
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
