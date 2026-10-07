// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8063: the outbound A2A bridge, driven against a strict stub A2A 1.0 agent.
//!
//! Every row starts a real `Backend` from an `a2a_url` config and talks to it
//! the way the invoke funnel does (`tools/list`, `tools/call`), so the rows pin
//! the transport the gateway actually starts, not a helper beside it.
#![cfg(feature = "a2a")]

use std::collections::HashMap;
use std::time::Duration;

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use serde_json::{Value, json};

mod common;
#[path = "a2a_outbound/stub.rs"]
mod stub;

use stub::{Agent, Answer};

/// The one tool an agent is exposed as (design r1: one tool per agent).
const TOOL: &str = "send_message";

fn backend(a2a_url: &str, card_path: Option<&str>, headers: &[(&str, &str)]) -> Backend {
    let config = BackendConfig {
        description: "stub A2A agent".into(),
        enabled: true,
        transport: TransportConfig::A2a {
            a2a_url: a2a_url.to_owned(),
            a2a_agent_card_path: card_path.map(str::to_owned),
        },
        stop_when_idle_for: None,
        max_frame_bytes: None,
        timeout: Duration::from_secs(10),
        env: HashMap::default(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        oauth: None,
        secrets: Vec::new(),
        passthrough: false,
        allow_cleartext_credentials: true,
        input_schema_enforcement: mcp_gateway::config::InputSchemaEnforcement::default(),
        allow_flagged_tools: std::collections::BTreeMap::new(),
        runtime_profile: None,
        identity_propagation: None,
        account: None,
        signature_chain: mcp_gateway::config::ChainMode::default(),
        chain_origins: Vec::new(),
        chain_signer: None,
    };
    Backend::new(
        "agent",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    )
}

/// `tools/call send_message {message}` through the backend; the JSON-RPC
/// `result`, or the error rendered as text so a row can assert on it.
async fn call(backend: &Backend, message: &str) -> Result<Value, String> {
    let params = json!({"name": TOOL, "arguments": {"message": message}});
    match backend.request("tools/call", Some(params)).await {
        Ok(response) => match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (_, Some(error)) => Err(format!("JSON-RPC {}: {}", error.code, error.message)),
            (None, None) => Err("empty response".into()),
        },
        Err(error) => Err(error.to_string()),
    }
}

fn texts(result: &Value) -> Vec<String> {
    result["content"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item["type"] == "text")
                .filter_map(|item| item["text"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn card_fetches(log: &stub::Log) -> usize {
    log.lock()
        .expect("log")
        .iter()
        .filter(|seen| seen.path != stub::RPC_PATH)
        .count()
}

/// A2A.1: an `a2a_url` backend starts, lists the agent as one tool, and a
/// `tools/call` reaches the agent as a conforming `SendMessage` whose answer
/// comes back as MCP text content.
#[tokio::test]
async fn a2a_1_a_call_reaches_the_agent_and_returns_its_answer() {
    let (base, log) = stub::serve(Agent::answering(stub::completed_task(
        json!([{"text": "sunny, 21 C"}]),
    )))
    .await;
    let backend = backend(&base, None, &[("x-api-key", "stub-key")]);

    let tools = backend.get_tools().await.expect("the agent's card lists");
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, [TOOL], "one tool per agent");
    let description = tools[0].description.clone().unwrap_or_default();
    assert!(
        description.contains("Answers a question"),
        "skills are discovery text on the one tool: {description}"
    );

    let result = call(&backend, "weather in Helsinki?")
        .await
        .expect("the call succeeds");
    assert_eq!(texts(&result), ["sunny, 21 C"], "result: {result}");
    assert_ne!(result["isError"], json!(true));

    let sends = stub::sends(&log);
    assert_eq!(sends.len(), 1, "exactly one SendMessage");
    let sent = &sends[0];
    assert_eq!(
        sent.headers.get("x-api-key").and_then(|v| v.to_str().ok()),
        Some("stub-key"),
        "configured headers reach the agent"
    );
    assert_eq!(
        sent.body.pointer("/params/message/parts/0/text"),
        Some(&json!("weather in Helsinki?"))
    );
}

/// A2A.4: every send carries a fresh `messageId`.
#[tokio::test]
async fn a2a_4_each_send_has_a_fresh_message_id() {
    let (base, log) = stub::serve(Agent::answering(stub::completed_task(
        json!([{"text": "ok"}]),
    )))
    .await;
    let backend = backend(&base, None, &[]);
    call(&backend, "one").await.expect("first call");
    call(&backend, "two").await.expect("second call");
    let ids: Vec<Value> = stub::sends(&log)
        .iter()
        .map(|seen| {
            seen.body
                .pointer("/params/message/messageId")
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1], "messageId is unique per send: {ids:?}");
}

/// A2A.2: `a2a_agent_card_path` is where the card is fetched from.
#[tokio::test]
async fn a2a_2_a_custom_card_path_is_fetched() {
    let mut agent = Agent::answering(stub::completed_task(json!([{"text": "custom"}])));
    agent.card_path = "/custom/card.json".into();
    let (base, log) = stub::serve(agent).await;
    let backend = backend(&base, Some("/custom/card.json"), &[]);

    let result = call(&backend, "hi").await.expect("the call succeeds");
    assert_eq!(texts(&result), ["custom"]);
    assert!(card_fetches(&log) >= 1, "the custom card path was fetched");
}

/// A2A.3a: a `SendMessage` answered with a redirect to another origin is
/// refused, and the redirect target is never contacted.
#[tokio::test]
async fn a2a_3a_a_cross_origin_redirect_is_refused_and_never_followed() {
    let (elsewhere, tripped) = stub::tripwire().await;
    let mut agent = Agent::answering(Value::Null);
    agent.answer = Answer::Redirect(format!("{elsewhere}/steal"));
    let (base, log) = stub::serve(agent).await;
    let backend = backend(&base, None, &[("authorization", "Bearer secret-token")]);

    let outcome = call(&backend, "hi").await;
    assert_eq!(
        stub::sends(&log).len(),
        1,
        "the agent was reached: {outcome:?}"
    );
    assert!(
        outcome.is_err(),
        "a redirected call does not succeed: {outcome:?}"
    );
    assert!(
        tripped.lock().expect("log").is_empty(),
        "the redirect target must never be contacted"
    );
}

/// A2A.3b/3c: the card's advertised endpoint is agent-supplied. Another
/// origin, including a metadata address, is refused before any request.
#[tokio::test]
async fn a2a_3b_a_cross_origin_advertised_endpoint_is_refused() {
    let (elsewhere, tripped) = stub::tripwire().await;
    for endpoint in [
        format!("{elsewhere}/a2a"),
        "http://169.254.169.254/a2a".to_owned(),
    ] {
        let mut agent = Agent::answering(stub::completed_task(json!([{"text": "no"}])));
        agent.endpoint = Some(endpoint.clone());
        let (base, log) = stub::serve(agent).await;
        let backend = backend(&base, None, &[("authorization", "Bearer secret-token")]);

        let outcome = call(&backend, "hi").await;
        assert!(
            card_fetches(&log) >= 1,
            "the card was read ({endpoint}): {outcome:?}"
        );
        let error = outcome.expect_err("a cross-origin endpoint is refused");
        assert!(
            error.contains("origin"),
            "the refusal names the origin rule ({endpoint}): {error}"
        );
        assert!(
            stub::sends(&log).is_empty(),
            "nothing was sent ({endpoint})"
        );
    }
    assert!(
        tripped.lock().expect("log").is_empty(),
        "the advertised endpoint was never contacted"
    );
}

/// A2A.4: a direct `{message}` reply is an answer like a completed task.
#[tokio::test]
async fn a2a_4_a_message_reply_is_an_answer() {
    let reply = json!({"message": {
        "messageId": "m-1", "contextId": "ctx-9", "role": "ROLE_AGENT",
        "parts": [{"text": "hello from a message"}]}});
    let (base, _log) = stub::serve(Agent::answering(reply)).await;
    let result = call(&backend(&base, None, &[]), "hi")
        .await
        .expect("the call succeeds");
    assert_eq!(texts(&result), ["hello from a message"], "result: {result}");
}

/// A2A.5: data, raw-file and url-file parts keep what they carry.
#[tokio::test]
async fn a2a_5_parts_become_mcp_content_without_loss() {
    let file_url = "https://files.stub-agent.test/r.pdf";
    let parts = json!([
        {"data": {"temperature": 21}},
        {"raw": "aGVsbG8gYnl0ZXM=", "mediaType": "text/plain", "filename": "note.txt"},
        {"url": file_url, "mediaType": "application/pdf", "filename": "r.pdf"}
    ]);
    let (base, _log) = stub::serve(Agent::answering(stub::completed_task(parts))).await;
    let result = call(&backend(&base, None, &[]), "hi")
        .await
        .expect("the call succeeds");

    assert_eq!(
        result["structuredContent"],
        json!({"temperature": 21}),
        "result: {result}"
    );
    let content = result["content"].as_array().cloned().unwrap_or_default();
    assert!(
        content.iter().any(|item| item["type"] == "resource"
            && item["resource"]["blob"] == "aGVsbG8gYnl0ZXM="
            && item["resource"]["mimeType"] == "text/plain"),
        "inline bytes are kept as an embedded resource: {result}"
    );
    assert!(
        content
            .iter()
            .any(|item| item["type"] == "resource_link" && item["uri"] == file_url),
        "a url part is a resource link: {result}"
    );
}

/// A2A.5: a task that did not complete is a tool error carrying the agent's
/// reason, so the model sees why.
#[tokio::test]
async fn a2a_5_unfinished_tasks_are_tool_errors_with_the_reason() {
    for (state, reason) in [
        ("TASK_STATE_FAILED", "upstream API down"),
        ("TASK_STATE_REJECTED", "out of scope for this agent"),
        ("TASK_STATE_CANCELED", "canceled by the agent"),
        ("TASK_STATE_INPUT_REQUIRED", "which city?"),
        ("TASK_STATE_AUTH_REQUIRED", "sign in at the agent first"),
    ] {
        let (base, _log) = stub::serve(Agent::answering(stub::task_in(state, reason))).await;
        let result = call(&backend(&base, None, &[]), "hi")
            .await
            .unwrap_or_else(|error| panic!("{state} is a tool result, not a failure: {error}"));
        assert_eq!(result["isError"], json!(true), "{state}: {result}");
        let text = texts(&result).join(" ");
        assert!(
            text.contains(reason),
            "{state} carries the agent's reason: {text}"
        );
    }
}

/// A2A.6: credentials in `a2a_url` never reach an error message.
#[tokio::test]
async fn a2a_6_url_credentials_are_redacted_from_errors() {
    // Nothing listens on this port: the card fetch fails and is reported.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    let port = listener.local_addr().expect("port").port();
    drop(listener);
    let secret = "hunter2-secret";
    let userinfo = ["operator", secret].join(":");
    let url = format!("http://{userinfo}@127.0.0.1:{port}");
    let error = call(&backend(&url, None, &[]), "hi")
        .await
        .expect_err("nothing answers");
    assert!(!error.contains(secret), "credential leaked: {error}");
}

/// A2A.5: `structuredContent` is an object or absent; a sole non-object data
/// part stays text only.
#[tokio::test]
async fn a2a_5_a_non_object_data_part_is_not_structured_content() {
    let parts = json!([{"data": [1, 2, 3]}]);
    let (base, _log) = stub::serve(Agent::answering(stub::completed_task(parts))).await;
    let result = call(&backend(&base, None, &[]), "hi")
        .await
        .expect("the call succeeds");
    assert!(
        result.get("structuredContent").is_none(),
        "an array is not structured content: {result}"
    );
    assert_eq!(
        texts(&result),
        ["[1,2,3]"],
        "the data stays as its JSON text: {result}"
    );
}

/// A2A.7: a delegation is a tool call to the gateway. Through `/mcp`
/// `gateway_invoke` it meets the same admission as any backend tool: a modern
/// side-effecting call without an idempotency key is refused before the agent
/// is contacted, and the same call with a key reaches the agent once.
#[tokio::test]
async fn a2a_7_a_delegation_passes_the_gateway_funnel() {
    let (base, log) = stub::serve(Agent::answering(stub::completed_task(
        json!([{"text": "governed"}]),
    )))
    .await;
    let (state, _store) = common::state(common::Fixture::default()).await;
    assert!(
        state
            .backends
            .register(std::sync::Arc::new(backend(&base, None, &[])))
    );
    let invoke = |key: Option<&str>| {
        let mut frame = common::modern(
            "tools/call",
            json!({"name": "gateway_invoke", "arguments": {
                "server": "agent", "tool": TOOL, "arguments": {"message": "hi"}}}),
        );
        if let Some(key) = key {
            frame["params"]["_meta"][mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META] =
                json!(key);
        }
        frame
    };

    let (_, refused) = common::post(&state, invoke(None), &[]).await;
    assert!(
        stub::sends(&log).is_empty(),
        "an unkeyed side-effecting call never reaches the agent: {refused}"
    );

    let (status, answered) = common::post(&state, invoke(Some("a2a-7-key")), &[]).await;
    assert!(status.is_success(), "{status}: {answered}");
    assert!(
        answered.to_string().contains("governed"),
        "the agent's answer comes back through the funnel: {answered}"
    );
    assert_eq!(
        stub::sends(&log).len(),
        1,
        "exactly one delegation reached the agent"
    );
}

/// A2A.4: a card interface that names a `tenant` gets it on every send.
#[tokio::test]
async fn a2a_4_the_cards_tenant_rides_every_send() {
    let mut agent = Agent::answering(stub::completed_task(json!([{"text": "tenant ok"}])));
    agent.tenant = Some("tenant-7".into());
    let (base, log) = stub::serve(agent).await;
    let result = call(&backend(&base, None, &[]), "hi")
        .await
        .expect("the call succeeds");
    assert_eq!(texts(&result), ["tenant ok"], "result: {result}");
    assert_eq!(
        stub::sends(&log)[0].body.pointer("/params/tenant"),
        Some(&json!("tenant-7"))
    );
}

/// A2A.7: identity propagation on an A2A backend is accepted at load, and a
/// per-request credential reaches the agent on that request alone.
#[tokio::test]
async fn a2a_7_a_propagated_credential_reaches_the_agent_per_request() {
    use mcp_gateway::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    let (base, log) = stub::serve(Agent::answering(stub::completed_task(
        json!([{"text": "ok"}]),
    )))
    .await;

    let mut config = mcp_gateway::config::Config::default();
    let mut backend_config = mcp_gateway::config::BackendConfig {
        transport: TransportConfig::A2a {
            a2a_url: base.clone(),
            a2a_agent_card_path: None,
        },
        allow_cleartext_credentials: true,
        ..mcp_gateway::config::BackendConfig::default()
    };
    backend_config.identity_propagation = Some(IdentityPropagationConfig {
        strategy: PropagationStrategyKind::Passthrough,
        audience: "agent".into(),
        required: true,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    });
    config.backends.insert("agent".into(), backend_config);
    config
        .validate()
        .expect("an A2A backend can carry a propagated credential");

    let backend = backend(&base, None, &[("authorization", "Bearer static")]);
    let params = json!({"name": TOOL, "arguments": {"message": "hi"}});
    let user = [("authorization".to_owned(), "Bearer user-1".to_owned())];
    backend
        .request_with_headers("tools/call", Some(params.clone()), &user, Some("user-1"))
        .await
        .expect("the propagated call succeeds");
    backend
        .request("tools/call", Some(params))
        .await
        .expect("the static call succeeds");

    let seen: Vec<Option<String>> = stub::sends(&log)
        .iter()
        .map(|sent| {
            sent.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        seen,
        [
            Some("Bearer user-1".to_owned()),
            Some("Bearer static".to_owned())
        ],
        "the user's credential replaces the static one on its request only"
    );
}
