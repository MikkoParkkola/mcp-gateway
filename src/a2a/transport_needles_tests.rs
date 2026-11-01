// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An A2A backend's injected values (DELTA-16): every answer and
//! error leaves the transport scrubbed, while task ids, context ids and the
//! card's routing fields are read and sent on as the agent gave them.
//!
//! A2A backends refuse `secrets:` rules at load, so each row seeds the
//! value straight into the set, on a real transport against a local agent.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::A2aTransport;
use crate::a2a::translator::TOOL_NAME;
use crate::security::needles::NeedleSet;
use crate::security::ssrf::DestinationPolicy;
use crate::transport::Transport;

const NEEDLE: &str = "a2a-echo-secret-61f3";

/// Every JSON-RPC body the agent received, in order.
type Seen = Arc<parking_lot::Mutex<Vec<Value>>>;

/// An agent on loopback whose card is `card(endpoint)` and whose every
/// JSON-RPC body is answered by `reply`.
async fn agent(card: fn(&str) -> Value, reply: fn(&Value) -> Value, seen: Seen) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    let endpoint = format!("{base}/a2a");
    let app = axum::Router::new()
        .route(
            "/.well-known/agent-card.json",
            axum::routing::get(move || {
                let card = card(&endpoint);
                async move { axum::Json(card) }
            }),
        )
        .route(
            "/a2a",
            axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                seen.lock().push(body.clone());
                let mut answer = reply(&body);
                answer["jsonrpc"] = json!("2.0");
                answer["id"] = body["id"].clone();
                async move { axum::Json(answer) }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    base
}

/// A 1.0 card at `endpoint` whose description and skill echo the needle.
fn echoing_card(endpoint: &str) -> Value {
    json!({"name": "echoes", "description": format!("uses {NEEDLE}"),
        "skills": [{"name": "s", "description": format!("key {NEEDLE}")}],
        "supportedInterfaces": [
            {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]})
}

/// A transport against `base` whose needle set holds `needle`.
async fn started(base: &str, needle: &str) -> crate::Result<Arc<A2aTransport>> {
    let needles = NeedleSet::with_grace(Duration::from_secs(3_600));
    needles.insert("echoes", needle);
    A2aTransport::start(
        base,
        None,
        &HashMap::new(),
        Duration::from_secs(30),
        DestinationPolicy::Configured,
        None,
        Some(Arc::new(needles)),
    )
    .await
}

async fn call(transport: &A2aTransport, params: Value) -> Value {
    let response = transport
        .request("tools/call", Some(params))
        .await
        .expect("an answer");
    serde_json::to_value(&response).expect("serialises")
}

fn send() -> Value {
    json!({"name": TOOL_NAME, "arguments": {"message": "hi"}})
}

/// T1.24: a `SendMessage` reply echoing the value reaches the caller
/// redacted, and so does an agent error quoting it.
#[tokio::test]
async fn a_reply_and_an_agent_error_echoing_the_value_are_redacted() {
    for reply in [
        (|_: &Value| {
            json!({"result": {"message": {"messageId": "m", "role": "ROLE_AGENT",
            "parts": [{"text": format!("your key is {NEEDLE}")}]}}})
        }) as fn(&Value) -> Value,
        |_: &Value| json!({"error": {"code": -32001, "message": format!("bad key {NEEDLE}")}}),
    ] {
        let base = agent(echoing_card, reply, Seen::default()).await;
        let transport = started(&base, NEEDLE).await.expect("starts");
        let text = call(&transport, send()).await.to_string();
        assert!(
            !text.contains(NEEDLE),
            "the echo reached the caller: {text}"
        );
        assert!(text.contains("[redacted]"), "not redacted: {text}");
    }
}

/// T1.25: the card's description and skill reach `initialize` and
/// `tools/list` redacted.
#[tokio::test]
async fn the_card_reaches_the_caller_redacted() {
    let base = agent(echoing_card, |_| json!({"result": {}}), Seen::default()).await;
    let transport = started(&base, NEEDLE).await.expect("starts");
    for method in ["initialize", "tools/list"] {
        let response = transport.request(method, None).await.expect("an answer");
        let text = serde_json::to_string(&response).expect("serialises");
        assert!(!text.contains(NEEDLE), "{method}: {text}");
    }
}

/// T1.34: a task whose id is the value is polled with the original id; every
/// copy the caller sees is redacted.
#[tokio::test]
async fn a_task_id_equal_to_the_value_is_polled_as_sent() {
    let seen = Seen::default();
    let base = agent(
        echoing_card,
        |body| {
            let state = if body["method"] == "GetTask" {
                "TASK_STATE_COMPLETED"
            } else {
                "TASK_STATE_WORKING"
            };
            let task = json!({"id": NEEDLE, "contextId": "c-1", "status": {"state": state},
                "artifacts": [{"parts": [{"text": format!("done {NEEDLE}")}]}]});
            if body["method"] == "GetTask" {
                json!({"result": task})
            } else {
                json!({"result": {"task": task}})
            }
        },
        Arc::clone(&seen),
    )
    .await;
    let transport = started(&base, NEEDLE).await.expect("starts");
    let text = call(&transport, send()).await.to_string();
    assert!(!text.contains(NEEDLE), "{text}");
    let seen = seen.lock();
    let polled = seen
        .iter()
        .find(|body| body["method"] == "GetTask")
        .expect("the task was polled");
    assert_eq!(
        polled["params"]["id"], NEEDLE,
        "the poll used a redacted id"
    );
}

/// T1.36 (DELTA-14): an interrupted task whose id and context id are the
/// value is resumed with both originals; the caller's copies are redacted.
#[tokio::test]
async fn a_resumed_task_is_sent_its_original_ids() {
    let seen = Seen::default();
    let base = agent(
        echoing_card,
        |body| {
            let resumed = body["params"]["message"]["taskId"].is_string();
            let state = if resumed {
                "TASK_STATE_COMPLETED"
            } else {
                "TASK_STATE_INPUT_REQUIRED"
            };
            json!({"result": {"task": {"id": NEEDLE, "contextId": NEEDLE,
                "status": {"state": state, "message": {"messageId": "m", "role": "ROLE_AGENT",
                    "parts": [{"text": format!("which {NEEDLE}?")}]}}}}})
        },
        Arc::clone(&seen),
    )
    .await;
    let transport = started(&base, NEEDLE).await.expect("starts");
    let asked = call(&transport, send()).await;
    assert!(!asked.to_string().contains(NEEDLE), "{asked}");
    let token = asked["result"]["requestState"].clone();
    assert!(token.is_string(), "premise: a question was asked: {asked}");
    let resumed = call(
        &transport,
        json!({"name": TOOL_NAME, "arguments": {"message": "hi"}, "requestState": token,
            "inputResponses": {"a2a_reply": {"action": "accept", "content": {"reply": "x"}}}}),
    )
    .await;
    assert!(!resumed.to_string().contains(NEEDLE), "{resumed}");
    let seen = seen.lock();
    let resume = seen.last().expect("the resume reached the agent");
    assert_eq!(resume["params"]["message"]["taskId"], NEEDLE);
    assert_eq!(resume["params"]["message"]["contextId"], NEEDLE);
}

/// T1.37 (DELTA-15): with a short value `1` that the card's protocol version
/// `1.0` contains, the endpoint is still chosen from the card as sent, and
/// the card text the caller sees is redacted.
#[tokio::test]
async fn routing_fields_are_read_from_the_card_as_sent() {
    let base = agent(
        |endpoint| {
            json!({"name": "agent", "description": "release 1",
            "supportedInterfaces": [
                {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]})
        },
        |_| json!({"result": {}}),
        Seen::default(),
    )
    .await;
    let transport = started(&base, "1")
        .await
        .expect("the card's routing is read as sent");
    let listed = transport
        .request("tools/list", None)
        .await
        .expect("an answer");
    let description = listed.result.expect("a result")["tools"][0]["description"].to_string();
    assert!(!description.contains('1'), "{description}");
}

/// T1.37b (DELTA-15): a start refused over the card's routing fields names
/// none of them raw.
#[tokio::test]
async fn a_routing_refusal_quotes_no_value() {
    let base = agent(
        |endpoint| {
            json!({"name": "agent", "supportedInterfaces": [
            {"url": endpoint, "protocolBinding": format!("GRPC-{NEEDLE}"), "protocolVersion": "1.0"}]})
        },
        |_| json!({"result": {}}),
        Seen::default(),
    )
    .await;
    let Err(error) = started(&base, NEEDLE).await else {
        panic!("premise: no JSONRPC interface, so the start is refused");
    };
    let text = error.to_string();
    assert!(
        text.contains("JSONRPC 1.x"),
        "premise: the routing refusal: {text}"
    );
    assert!(
        !text.contains(NEEDLE),
        "the refusal quotes the card: {text}"
    );
}
