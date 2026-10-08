// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stub A2A 1.0 agent (JSON-RPC binding) that validates every request
//! strictly and records it. Included by `#[path]` from `a2a_outbound.rs`.
//!
//! Strict on purpose: a request the A2A 1.0 specification (tag v1.0.1) would
//! not accept is answered `-32602`, so a gateway that speaks an older dialect
//! fails the row instead of passing against a lenient fixture.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};

/// One request the stub received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub path: String,
    pub headers: HeaderMap,
    pub body: Value,
}

pub type Log = Arc<Mutex<Vec<Seen>>>;

/// The RPC path every stub card advertises unless a row overrides it.
pub const RPC_PATH: &str = "/a2a";
/// The A2A 1.0 well-known card path.
pub const CARD_PATH: &str = "/.well-known/agent-card.json";

/// Why `body` is not an A2A 1.0 `SendMessage`, or `None` when it is.
pub fn send_message_violation(headers: &HeaderMap, body: &Value) -> Option<String> {
    if headers.get("a2a-version").and_then(|v| v.to_str().ok()) != Some("1.0") {
        return Some("missing or wrong A2A-Version header".into());
    }
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || body.get("id").is_none() {
        return Some("not a JSON-RPC 2.0 request".into());
    }
    if body.get("method").and_then(Value::as_str) != Some("SendMessage") {
        return Some(format!("unexpected method {:?}", body.get("method")));
    }
    let Some(message) = body.pointer("/params/message") else {
        return Some("params.message missing".into());
    };
    if message.get("kind").is_some() {
        return Some("`kind` is A2A 0.3 vocabulary".into());
    }
    if message
        .get("messageId")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Some("message.messageId missing or empty".into());
    }
    if message.get("role").and_then(Value::as_str) != Some("ROLE_USER") {
        return Some("message.role is not ROLE_USER".into());
    }
    let Some(parts) = message.get("parts").and_then(Value::as_array) else {
        return Some("message.parts missing".into());
    };
    if parts.is_empty() {
        return Some("message.parts is empty".into());
    }
    for part in parts {
        let fields = ["text", "raw", "url", "data"]
            .iter()
            .filter(|field| part.get(**field).is_some())
            .count();
        if fields != 1 {
            return Some("a part must carry exactly one of text, raw, url, data".into());
        }
    }
    None
}

/// What the stub answers a valid `SendMessage` with.
#[derive(Clone)]
pub enum Answer {
    /// A JSON-RPC `result` (a `{task}` or `{message}` object).
    Result(Value),
    /// An HTTP 307 to this location.
    Redirect(String),
}

/// How one stub agent behaves.
#[derive(Clone)]
pub struct Agent {
    /// Where the card is served. Every other path is 404.
    pub card_path: String,
    /// The JSON-RPC interface URL the card advertises; `None` = own `RPC_PATH`.
    pub endpoint: Option<String>,
    /// The `tenant` the card's interface names; a send without it is refused.
    pub tenant: Option<String>,
    pub answer: Answer,
}

impl Agent {
    pub fn answering(result: Value) -> Self {
        Self {
            card_path: CARD_PATH.into(),
            endpoint: None,
            tenant: None,
            answer: Answer::Result(result),
        }
    }
}

/// A completed task whose one artifact carries `parts`.
pub fn completed_task(parts: Value) -> Value {
    let mut task = json!({"task": {
        "id": "task-1",
        "contextId": "ctx-1",
        "status": {"state": "TASK_STATE_COMPLETED"},
        "artifacts": [{"artifactId": "art-1"}],
    }});
    task["task"]["artifacts"][0]["parts"] = parts;
    task
}

/// A task that ended in `state` with an agent status message `text`.
pub fn task_in(state: &str, text: &str) -> Value {
    json!({"task": {
        "id": "task-2",
        "contextId": "ctx-2",
        "status": {"state": state, "message": {
            "messageId": "m-agent", "role": "ROLE_AGENT", "parts": [{"text": text}]}},
    }})
}

fn card(agent: &Agent, base: &str) -> Value {
    let endpoint = agent
        .endpoint
        .clone()
        .unwrap_or_else(|| format!("{base}{RPC_PATH}"));
    let mut interface =
        json!({"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"});
    if let Some(tenant) = &agent.tenant {
        interface["tenant"] = json!(tenant);
    }
    json!({
        "name": "Stub Agent",
        "description": "Answers questions for the outbound bridge rows.",
        "version": "1.0.0",
        "supportedInterfaces": [interface],
        "capabilities": {},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{
            "id": "answer", "name": "Answer", "description": "Answers a question",
            "tags": ["qa"]
        }],
    })
}

fn rpc(agent: &Agent, headers: &HeaderMap, body: &Value) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let tenant_missing = agent.tenant.as_ref().is_some_and(|tenant| {
        body.pointer("/params/tenant").and_then(Value::as_str) != Some(tenant.as_str())
    });
    let violation = send_message_violation(headers, body)
        .or_else(|| tenant_missing.then(|| "params.tenant does not match the card".to_owned()));
    if let Some(why) = violation {
        return axum::Json(json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32602, "message": why}}))
        .into_response();
    }
    match &agent.answer {
        Answer::Result(result) => {
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
        }
        Answer::Redirect(location) => (
            StatusCode::TEMPORARY_REDIRECT,
            [(axum::http::header::LOCATION, location.clone())],
        )
            .into_response(),
    }
}

/// Serve `agent` on a fresh loopback port; returns its base URL and log.
pub async fn serve(agent: Agent) -> (String, Log) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub agent");
    let base = format!("http://{}", listener.local_addr().expect("stub address"));
    let log: Log = Arc::default();
    let (card_log, rpc_log) = (Arc::clone(&log), Arc::clone(&log));
    let card_path = agent.card_path.clone();
    let (card_agent, card_base, rpc_agent) = (agent.clone(), base.clone(), agent);
    let app = Router::new()
        .route(
            &card_path,
            get(move |headers: HeaderMap| async move {
                card_log.lock().expect("log").push(Seen {
                    path: card_agent.card_path.clone(),
                    headers,
                    body: Value::Null,
                });
                axum::Json(card(&card_agent, &card_base))
            }),
        )
        .route(
            RPC_PATH,
            post(
                move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| async move {
                    let response = rpc(&rpc_agent, &headers, &body);
                    rpc_log.lock().expect("log").push(Seen {
                        path: RPC_PATH.into(),
                        headers,
                        body,
                    });
                    response
                },
            ),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, log)
}

/// A server that only counts what reaches it: the "must never be contacted"
/// target of the redirect and cross-origin rows.
pub async fn tripwire() -> (String, Log) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tripwire");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("tripwire address")
    );
    let log: Log = Arc::default();
    let hits = Arc::clone(&log);
    let app = Router::new().fallback(move |uri: axum::http::Uri, headers: HeaderMap| async move {
        hits.lock().expect("log").push(Seen {
            path: uri.path().to_owned(),
            headers,
            body: Value::Null,
        });
        StatusCode::OK
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, log)
}

/// The `SendMessage` bodies the stub accepted or refused, in order.
pub fn sends(log: &Log) -> Vec<Seen> {
    log.lock()
        .expect("log")
        .iter()
        .filter(|seen| seen.path == RPC_PATH)
        .cloned()
        .collect()
}
