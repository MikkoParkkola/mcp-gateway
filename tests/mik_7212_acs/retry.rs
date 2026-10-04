// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::mrtr::RetryFields;
use serde_json::json;

#[test]
fn ac_mrtr_1_a_retry_carries_its_inputs_and_state() {
    let params = json!({
        "name": "get_weather",
        "arguments": { "location": "Helsinki" },
        "inputResponses": {
            "confirm": { "action": "accept", "content": { "ok": true } }
        },
        "requestState": "opaque-envelope"
    });

    let fields = RetryFields::from_params(Some(&params));
    assert_eq!(fields.request_state.as_deref(), Some("opaque-envelope"));
    assert!(
        fields
            .input_responses
            .as_ref()
            .is_some_and(|r| r.get("confirm").is_some()),
        "the client's answers must reach the backend that asked for them"
    );
}

#[test]
fn ac_mrtr_1_an_ordinary_call_carries_neither() {
    // The common case stays exactly as it was: no retry fields, no change.
    let fields = RetryFields::from_params(Some(&json!({
        "name": "get_weather", "arguments": {}
    })));
    assert!(fields.request_state.is_none());
    assert!(fields.input_responses.is_none());
    assert!(!fields.is_retry(), "an ordinary call is not a retry");
}

#[test]
fn ac_mrtr_1_either_field_alone_marks_a_retry() {
    // The spec: a server MUST include at least one of `inputRequests` or
    // `requestState`, so a retry may legitimately carry only one back.
    // Requiring both would drop the state-only retry, which is the shape a
    // server uses when it needs no further input.
    let state_only = RetryFields::from_params(Some(&json!({
        "name": "t", "requestState": "envelope"
    })));
    assert!(state_only.is_retry());

    let inputs_only = RetryFields::from_params(Some(&json!({
        "name": "t", "inputResponses": { "a": {} }
    })));
    assert!(inputs_only.is_retry());
}

#[test]
fn ac_mrtr_1_a_non_string_request_state_is_not_read_as_one() {
    // `requestState` is a string the client echoes verbatim. A client that
    // sends an object has not echoed anything, and coercing it would put a
    // shape the gateway invented where the backend's own state belongs.
    let fields = RetryFields::from_params(Some(&json!({
        "name": "t", "requestState": { "not": "a string" }
    })));
    assert!(fields.request_state.is_none());
}
