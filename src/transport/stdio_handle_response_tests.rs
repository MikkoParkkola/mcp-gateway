// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `handle_response`: routing a stdio line to its pending caller, split out of
//! `stdio_tests.rs` to keep it under the file-size ceiling.

use super::*;

#[test]
fn handle_response_routes_to_pending_request() {
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("1".to_string(), tx);

    let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
    t.handle_response(json).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[test]
fn handle_response_string_id() {
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("req-42".to_string(), tx);

    let json = r#"{"jsonrpc":"2.0","id":"req-42","result":{}}"#;
    t.handle_response(json).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.result.is_some());
}

/// An inbound request that happens to carry an `id` must never be routed to
/// a pending caller as if it were that caller's answer. The frame is a
/// server-to-client request (`sampling/createMessage`), not a response.
#[test]
fn handle_response_rejects_inbound_request_and_leaves_caller_pending() {
    // GIVEN: a caller waiting on id 5
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("5".to_string(), tx);

    // WHEN: the peer sends a *request* that reuses that id
    let json = r#"{"jsonrpc":"2.0","id":5,"method":"sampling/createMessage","params":{}}"#;
    let outcome = t.handle_response(json);

    // THEN: the frame is refused, and the caller is still waiting
    assert!(
        outcome.is_err(),
        "a frame carrying `method` must not parse as a response"
    );
    assert!(rx.try_recv().is_err(), "caller must not be completed");
    assert!(
        t.pending.contains_key("5"),
        "caller must remain pending, not be silently consumed"
    );
}

#[test]
fn handle_response_no_matching_pending() {
    let t = make_transport("echo");
    // No pending request registered - should not panic
    let json = r#"{"jsonrpc":"2.0","id":99,"result":{}}"#;
    t.handle_response(json).unwrap();
}

#[test]
fn handle_response_no_id_notification() {
    let t = make_transport("echo");
    // Notifications have no id - should be handled gracefully
    let json = r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#;
    t.handle_response(json).unwrap();
}

#[test]
fn handle_response_error_response() {
    let t = make_transport("echo");
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    t.pending.insert("5".to_string(), tx);

    let json = r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"Method not found"}}"#;
    t.handle_response(json).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.error.is_some());
    assert_eq!(response.error.unwrap().code, -32601);
}

#[test]
fn handle_response_invalid_json_returns_error() {
    let t = make_transport("echo");
    let result = t.handle_response("not valid json");
    assert!(result.is_err());
}
