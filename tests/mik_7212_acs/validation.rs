// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::extensions::ExtensionSet;
use mcp_gateway::protocol::mrtr::RetryFields;
use serde_json::json;

#[test]
fn a_retry_field_that_is_present_and_unusable_is_neither_a_retry_nor_a_fresh_call() {
    // The two fields used to fail differently for the same mistake: a
    // malformed `inputResponses` was carried through as a retry, while a
    // malformed `requestState` vanished and the call became a fresh one.
    // A retry that silently becomes a fresh call repeats whatever the first
    // attempt already did.
    for bad in [json!("answers"), json!(7), json!([]), json!(null)] {
        let fields = RetryFields::from_params(Some(&json!({ "inputResponses": bad })));
        assert!(
            fields.is_malformed(),
            "inputResponses {bad} must be refused"
        );
        assert!(fields.input_responses.is_none());
    }

    let fields = RetryFields::from_params(Some(&json!({ "requestState": { "a": 1 } })));
    assert!(
        fields.is_malformed(),
        "a non-string requestState must be refused, not dropped"
    );
}

#[test]
fn a_well_formed_retry_is_unaffected() {
    let fields = RetryFields::from_params(Some(&json!({
        "inputResponses": { "confirm": { "action": "accept" } },
        "requestState": "sealed-envelope"
    })));

    assert!(!fields.is_malformed());
    assert!(fields.is_retry());
    assert_eq!(fields.request_state.as_deref(), Some("sealed-envelope"));
}

#[test]
fn an_extension_whose_settings_are_not_an_object_is_not_negotiated() {
    // Presence is not agreement. A key whose value is unusable switched on
    // behaviour the peer never validly declared.
    for bad in [json!(null), json!(true), json!(3), json!("on"), json!([])] {
        let caps = json!({ "extensions": { "io.modelcontextprotocol/tasks": bad } });
        assert!(
            ExtensionSet::from_capabilities(&caps).is_empty(),
            "settings {bad} must not count as a declaration"
        );
    }
}

#[test]
fn an_extension_with_object_settings_is_negotiated() {
    let caps = json!({ "extensions": { "io.modelcontextprotocol/tasks": {} } });
    assert!(
        !ExtensionSet::from_capabilities(&caps).is_empty(),
        "a well-formed declaration must still be read"
    );
}
