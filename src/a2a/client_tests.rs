// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Endpoint selection, the origin rule and reply decoding.

use serde_json::json;

use super::*;

fn client(a2a_url: &str) -> A2aClient {
    A2aClient::new(a2a_url, None, Vec::new(), reqwest::Client::new()).unwrap()
}

fn card(interfaces: &serde_json::Value) -> AgentCard {
    serde_json::from_value(json!({"name": "a", "supportedInterfaces": interfaces})).unwrap()
}

#[test]
fn the_first_jsonrpc_1_x_interface_on_the_configured_origin_is_chosen() {
    let chosen = client("https://agent.invalid")
        .endpoint(&card(&json!([
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
            .endpoint(&card(&json!([
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
        .endpoint(&card(&json!([
            {"url": "https://agent.invalid/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
        ])))
        .unwrap_err()
        .to_string();
    assert!(error.contains("JSONRPC 0.3"), "{error}");
}

/// A real A2A 0.3 card has no `supportedInterfaces`: it states its version
/// and binding once, at the top. The refusal still names them.
#[test]
fn a_0_3_card_is_refused_naming_its_top_level_version() {
    let card: AgentCard = serde_json::from_value(json!({
        "name": "legacy",
        "url": "https://agent.invalid/a2a",
        "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC",
        "capabilities": {},
        "skills": []
    }))
    .unwrap();
    let error = client("https://agent.invalid")
        .endpoint(&card)
        .unwrap_err()
        .to_string();
    assert!(error.contains("offered: [JSONRPC 0.3.0]"), "{error}");
}

/// A 0.3 card's binding defaults to JSON-RPC, and an explicit one is named.
#[test]
fn a_0_3_card_names_its_default_or_stated_binding() {
    for (fields, offered) in [
        (json!({}), "offered: [JSONRPC 0.3.0]"),
        (
            json!({"preferredTransport": "GRPC"}),
            "offered: [GRPC 0.3.0]",
        ),
    ] {
        let mut value = json!({"name": "legacy", "protocolVersion": "0.3.0"});
        value
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let card: AgentCard = serde_json::from_value(value).unwrap();
        let error = client("https://agent.invalid")
            .endpoint(&card)
            .unwrap_err()
            .to_string();
        assert!(error.contains(offered), "{error}");
    }
}

/// Top-level 0.3 fields never outvote a JSON-RPC 1.x interface on the card.
#[test]
fn a_card_with_legacy_fields_and_a_1_x_interface_still_chooses_it() {
    let card: AgentCard = serde_json::from_value(json!({
        "name": "both",
        "protocolVersion": "0.3.0",
        "preferredTransport": "JSONRPC",
        "supportedInterfaces": [
            {"url": "https://agent.invalid/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ]
    }))
    .unwrap();
    let chosen = client("https://agent.invalid").endpoint(&card).unwrap();
    assert_eq!(chosen.url, "https://agent.invalid/a2a");
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
    let Reply::AgentError { code, message } = decode_reply(&json!({
        "jsonrpc": "2.0", "id": "1", "error": {"code": -32001, "message": "task not found"}}))
    .unwrap() else {
        panic!("an error envelope is the agent's error");
    };
    assert_eq!((code, message.as_str()), (-32001, "task not found"));

    assert!(decode_reply(&json!({"jsonrpc": "2.0", "id": "1", "result": {}})).is_err());
    assert!(decode_reply(&json!({"jsonrpc": "2.0", "id": "1"})).is_err());
    assert!(matches!(
        decode_reply(&json!({"jsonrpc": "2.0", "id": "1", "result": {"message": {
            "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "x"}]}}}))
        .unwrap(),
        Reply::Answer(_)
    ));
}

#[test]
fn the_card_sits_at_the_origin_whatever_a2a_url_carries() {
    let client = A2aClient::new(
        "https://agent.invalid/rpc/v1?token=x#frag",
        None,
        Vec::new(),
        reqwest::Client::new(),
    )
    .unwrap();
    assert_eq!(
        client.card_url,
        "https://agent.invalid/.well-known/agent-card.json"
    );
}

fn authorization(client: &A2aClient) -> Vec<&str> {
    client
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str())
        .collect()
}

#[test]
fn url_credentials_become_one_basic_header_and_leave_every_url() {
    let userinfo = ["operator", "s3cret"].join(":");
    let configured = A2aClient::new(
        &format!("https://{userinfo}@agent.invalid"),
        None,
        Vec::new(),
        reqwest::Client::new(),
    )
    .unwrap();
    // base64("operator:s3cret")
    assert_eq!(authorization(&configured), ["Basic b3BlcmF0b3I6czNjcmV0"]);
    assert!(
        !configured.card_url.contains("s3cret"),
        "{}",
        configured.card_url
    );
    let chosen = configured
        .endpoint(&card(&json!([
            {"url": "https://intruder:x@agent.invalid/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ])))
        .unwrap();
    assert_eq!(
        chosen.url, "https://agent.invalid/a2a",
        "no userinfo on the wire URL"
    );
}

#[test]
fn an_explicit_authorization_header_wins_over_url_credentials() {
    let explicit = vec![("authorization".to_owned(), "Bearer configured".to_owned())];
    let configured = A2aClient::new(
        "https://operator:pw@agent.invalid",
        None,
        explicit,
        reqwest::Client::new(),
    )
    .unwrap();
    assert_eq!(authorization(&configured), ["Bearer configured"]);
}

#[test]
fn a_password_only_url_still_authenticates() {
    let configured = A2aClient::new(
        "https://:only-pw@agent.invalid",
        None,
        Vec::new(),
        reqwest::Client::new(),
    )
    .unwrap();
    // base64(":only-pw")
    assert_eq!(authorization(&configured), ["Basic Om9ubHktcHc="]);
}

fn response(body: Vec<u8>) -> reqwest::Response {
    reqwest::Response::from(
        axum::http::Response::builder()
            .status(200)
            .body(body)
            .expect("fixture response builds"),
    )
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused_and_one_at_it_is_read() {
    let over = vec![b' '; MAX_BODY_BYTES + 1];
    let error = read_capped_json(response(over), "reply").await.unwrap_err();
    assert!(error.to_string().contains("exceeds"), "{error}");

    let mut at = vec![b' '; MAX_BODY_BYTES - 2];
    at.extend_from_slice(b"{}");
    assert_eq!(
        read_capped_json(response(at), "reply").await.unwrap(),
        json!({})
    );
}

#[test]
fn a_null_error_beside_a_result_is_a_success() {
    let reply = decode_reply(&json!({"jsonrpc": "2.0", "id": "1", "error": null,
        "result": {"message": {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "ok"}]}}}));
    assert!(
        matches!(reply, Ok(Reply::Answer(_))),
        "an error of null is no error"
    );
}
