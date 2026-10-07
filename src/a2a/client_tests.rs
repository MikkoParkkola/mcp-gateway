// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Endpoint selection, the origin rule and reply decoding.

use serde_json::json;

use super::*;

fn client(a2a_url: &str) -> A2aClient {
    A2aClient::new(a2a_url, None, Vec::new(), reqwest::Client::new()).unwrap()
}

fn card(interfaces: serde_json::Value) -> AgentCard {
    serde_json::from_value(json!({"name": "a", "supportedInterfaces": interfaces})).unwrap()
}

#[test]
fn the_first_jsonrpc_1_x_interface_on_the_configured_origin_is_chosen() {
    let chosen = client("https://agent.invalid")
        .endpoint(&card(json!([
            {"url": "https://agent.invalid/grpc", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
            {"url": "https://agent.invalid/old", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"},
            {"url": "https://agent.invalid/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
             "tenant": "t-1"}
        ])))
        .unwrap();
    assert_eq!(chosen.url, "https://agent.invalid/a2a");
    assert_eq!(chosen.tenant.as_deref(), Some("t-1"));
}

#[test]
fn an_advertised_endpoint_on_another_origin_is_refused() {
    let configured = client("https://agent.invalid");
    for url in [
        "https://other.invalid/a2a",
        "http://agent.invalid/a2a",
        "https://agent.invalid:8443/a2a",
        "http://169.254.169.254/a2a",
        "not a url",
    ] {
        let error = configured
            .endpoint(&card(json!([
                {"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
            ])))
            .unwrap_err()
            .to_string();
        assert!(error.contains("origin"), "{url}: {error}");
    }
}

#[test]
fn a_card_with_no_usable_interface_names_what_it_offers() {
    let error = client("https://agent.invalid")
        .endpoint(&card(json!([
            {"url": "https://agent.invalid/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
        ])))
        .unwrap_err()
        .to_string();
    assert!(error.contains("JSONRPC 0.3"), "{error}");
}

#[test]
fn a_card_path_must_be_a_path() {
    for path in ["card.json", "https://elsewhere.invalid/card.json"] {
        assert!(
            A2aClient::new(
                "https://agent.invalid",
                Some(path),
                Vec::new(),
                reqwest::Client::new()
            )
            .is_err(),
            "{path}"
        );
    }
}

#[test]
fn an_agent_error_is_the_agents_and_a_result_is_one_of_task_or_message() {
    let Reply::AgentError { code, message } = decode_reply(json!({
        "jsonrpc": "2.0", "id": "1", "error": {"code": -32001, "message": "task not found"}}))
    .unwrap() else {
        panic!("an error envelope is the agent's error");
    };
    assert_eq!((code, message.as_str()), (-32001, "task not found"));

    assert!(decode_reply(json!({"jsonrpc": "2.0", "id": "1", "result": {}})).is_err());
    assert!(decode_reply(json!({"jsonrpc": "2.0", "id": "1"})).is_err());
    assert!(matches!(
        decode_reply(json!({"jsonrpc": "2.0", "id": "1", "result": {"message": {
            "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "x"}]}}}))
        .unwrap(),
        Reply::Answer(_)
    ));
}
