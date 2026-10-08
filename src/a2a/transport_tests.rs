// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The transport's own contract: close aborts, ping is live, the rest is -32601.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::routing::{get, post};
use serde_json::{Value, json};

use crate::a2a::delegation::PARKED_TTL;

use super::*;

/// An agent whose card is served and counted, and whose RPC never answers.
/// `reached` is notified when a `SendMessage` arrives.
async fn hanging_agent() -> (String, Arc<AtomicUsize>, Arc<tokio::sync::Notify>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fetches = Arc::new(AtomicUsize::new(0));
    let reached = Arc::new(tokio::sync::Notify::new());
    let (counted, endpoint) = (Arc::clone(&fetches), format!("{base}/a2a"));
    let arrived = Arc::clone(&reached);
    let app = Router::new()
        .route(
            "/.well-known/agent-card.json",
            get(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                let endpoint = endpoint.clone();
                async move {
                    axum::Json(json!({"name": "hang", "supportedInterfaces": [
                        {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}))
                }
            }),
        )
        .route(
            "/a2a",
            post(move || {
                arrived.notify_one();
                std::future::pending::<String>()
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, fetches, reached)
}

async fn started(base: &str) -> Arc<A2aTransport> {
    A2aTransport::start(
        base,
        None,
        &HashMap::new(),
        Duration::from_secs(60),
        DestinationPolicy::Configured,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn close_aborts_an_in_flight_call() {
    let (base, _, reached) = hanging_agent().await;
    let transport = started(&base).await;
    let pending = tokio::spawn({
        let transport = Arc::clone(&transport);
        async move {
            let params = json!({"name": TOOL_NAME, "arguments": {"message": "hi"}});
            transport.request("tools/call", Some(params)).await
        }
    });
    // Closed only once the agent holds the request: the row proves an
    // in-flight call is aborted, not one that had not left yet.
    tokio::time::timeout(Duration::from_secs(5), reached.notified())
        .await
        .expect("the call reaches the agent");
    transport.close().await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("close ends the call well before the 60 s timeout")
        .unwrap();
    assert!(
        outcome.is_err(),
        "a closed transport does not answer: {outcome:?}"
    );
    assert!(!transport.is_connected());
}

#[tokio::test]
async fn ping_is_a_live_card_fetch() {
    let (base, fetches, _) = hanging_agent().await;
    let transport = started(&base).await;
    let before = fetches.load(Ordering::SeqCst);
    let response = transport.request("ping", None).await.unwrap();
    assert_eq!(response.result, Some(json!({})));
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        before + 1,
        "ping reached the agent"
    );
}

#[tokio::test]
async fn initialize_is_synthetic_and_other_methods_are_not_found() {
    let (base, _, _) = hanging_agent().await;
    let transport = started(&base).await;
    let init = transport.request("initialize", None).await.unwrap();
    let init = init.result.unwrap();
    assert_eq!(init["serverInfo"]["name"], "hang");
    assert_eq!(init["capabilities"], json!({"tools": {}}));
    for method in ["server/discover", "resources/list", "prompts/list"] {
        let response = transport.request(method, None).await.unwrap();
        assert_eq!(response.error.map(|e| e.code), Some(-32601), "{method}");
    }
}

#[tokio::test]
async fn an_unknown_tool_or_a_missing_message_is_invalid_params() {
    let (base, _, _) = hanging_agent().await;
    let transport = started(&base).await;
    for params in [
        json!({"name": "other", "arguments": {"message": "hi"}}),
        json!({"name": TOOL_NAME, "arguments": {}}),
    ] {
        let response = transport
            .request("tools/call", Some(params.clone()))
            .await
            .unwrap();
        assert_eq!(response.error.map(|e| e.code), Some(-32602), "{params}");
    }
}

/// An agent that asks a question on every `SendMessage` and records the ids
/// of the tasks it is asked to cancel.
async fn asking_agent() -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let canceled = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let (seen, endpoint) = (Arc::clone(&canceled), format!("{base}/a2a"));
    let app = Router::new()
        .route(
            "/.well-known/agent-card.json",
            get(move || {
                let endpoint = endpoint.clone();
                async move {
                    axum::Json(json!({"name": "asks", "supportedInterfaces": [
                        {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}))
                }
            }),
        )
        .route(
            "/a2a",
            post(move |axum::Json(body): axum::Json<Value>| {
                let seen = Arc::clone(&seen);
                async move {
                    let id = body["id"].clone();
                    if body["method"] == "CancelTask" {
                        seen.lock().push(body["params"]["id"].as_str().unwrap_or_default().to_owned());
                    }
                    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {"task": {
                        "id": "asked-1", "contextId": "c-1",
                        "status": {"state": "TASK_STATE_INPUT_REQUIRED", "message": {
                            "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "which?"}]}}}}}))
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, canceled)
}

/// MIK-8063 D1: a question nobody answers has its agent task canceled by the
/// sweep once its token expires, and the token is then refused.
#[tokio::test]
async fn an_abandoned_question_is_canceled_by_the_sweep() {
    let (base, canceled) = asking_agent().await;
    let transport = started(&base).await;
    let params = json!({"name": TOOL_NAME, "arguments": {"message": "hi"}});
    let asked = transport
        .request("tools/call", Some(params))
        .await
        .unwrap()
        .result
        .unwrap();
    assert_eq!(asked["resultType"], "input_required", "{asked}");
    let token = asked["requestState"].clone();

    transport.sweep(std::time::Instant::now());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(canceled.lock().is_empty(), "a fresh question is not swept");

    transport.sweep(std::time::Instant::now() + PARKED_TTL);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while canceled.lock().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the expired task was never canceled"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(canceled.lock().as_slice(), ["asked-1"]);

    let retry = json!({"name": TOOL_NAME, "arguments": {"message": "hi"}, "requestState": token,
        "inputResponses": {"a2a_reply": {"action": "accept", "content": {"reply": "x"}}}});
    let refused = transport.request("tools/call", Some(retry)).await.unwrap();
    assert_eq!(refused.error.map(|e| e.code), Some(-32602));
}

/// MIK-8063: closing the backend cancels every question still waiting, and
/// the cancel has reached the agent by the time `close` returns, so a
/// shutdown that follows cannot abort it.
#[tokio::test]
async fn close_cancels_waiting_questions() {
    let (base, canceled) = asking_agent().await;
    let transport = started(&base).await;
    let params = json!({"name": TOOL_NAME, "arguments": {"message": "hi"}});
    transport.request("tools/call", Some(params)).await.unwrap();
    transport.close().await.unwrap();
    assert_eq!(canceled.lock().as_slice(), ["asked-1"]);
}

/// MIK-8063: a transport dropped without `close` still cancels the task of a
/// question waiting on its caller.
#[tokio::test]
async fn a_dropped_transport_cancels_waiting_questions() {
    let (base, canceled) = asking_agent().await;
    let transport = started(&base).await;
    let params = json!({"name": TOOL_NAME, "arguments": {"message": "hi"}});
    transport.request("tools/call", Some(params)).await.unwrap();
    drop(transport);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while canceled.lock().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dropped transport never canceled the question"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(canceled.lock().as_slice(), ["asked-1"]);
}

/// MIK-8063 A2A.3: under the hardened policy a literal private `a2a_url` is
/// refused at start, before anything connects (no server listens there).
#[tokio::test]
async fn a_private_literal_a2a_url_is_refused_under_the_hardened_policy() {
    for url in [
        "http://169.254.169.254",
        "http://10.0.0.7:8080",
        "http://127.0.0.1:9",
    ] {
        let refused = A2aTransport::start(
            url,
            None,
            &HashMap::new(),
            Duration::from_secs(5),
            DestinationPolicy::Public,
        )
        .await;
        let Err(error) = refused else {
            panic!("{url} must be refused under the hardened policy");
        };
        assert!(
            error
                .to_string()
                .contains(crate::security::ssrf::SSRF_BLOCKED),
            "{url}: {error}"
        );
    }
}
