// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! On the direct route, a backend's own -32001 refusal,
//! carried on a non-retry status, is the backend's error, not a denial the
//! gateway made.

use super::*;

/// The error a peer's 400 JSON-RPC body with code -32001 becomes in the HTTP
/// transport, through the production `peer_refusal`.
fn peer_400() -> crate::Error {
    let body = json!({
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32001, "message": "backend says no"}
    })
    .to_string();
    crate::transport::peer_refusal_for_test(
        &body,
        &crate::protocol::RequestId::Number(1),
        reqwest::StatusCode::BAD_REQUEST,
    )
    .expect("premise: a 400 body answering this request is surfaced")
}

/// A1: the invocation record says `error` with the backend's code; the
/// gateway's own -32001 denial still records `denied` (control:
/// delivery.rs `a_withheld_direct_delivery_joins_its_denied_record`).
#[tokio::test]
async fn a_backends_minus_32001_refusal_is_audited_as_an_error() {
    let fx = fixture(Setup {
        backend_fail: Some(peer_400),
        ..Setup::default()
    })
    .await;
    let (_, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(
        body["error"]["code"], -32001,
        "premise: the peer's code: {body}"
    );
    let entry = only_invocation(&fx);
    assert_eq!(entry["outcome"], "error", "{entry}");
    assert_eq!(entry["error_code"], -32001, "{entry}");
}
