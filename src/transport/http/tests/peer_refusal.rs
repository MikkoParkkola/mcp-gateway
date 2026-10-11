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
