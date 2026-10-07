// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The transport's own contract: close aborts, ping is live, the rest is -32601.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::routing::{get, post};
use serde_json::json;

use super::*;

/// An agent whose card is served and counted, and whose RPC never answers.
async fn hanging_agent() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fetches = Arc::new(AtomicUsize::new(0));
    let (counted, endpoint) = (Arc::clone(&fetches), format!("{base}/a2a"));
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
        .route("/a2a", post(std::future::pending::<String>));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, fetches)
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
    let (base, _) = hanging_agent().await;
    let transport = started(&base).await;
    let pending = tokio::spawn({
        let transport = Arc::clone(&transport);
        async move {
            let params = json!({"name": TOOL_NAME, "arguments": {"message": "hi"}});
            transport.request("tools/call", Some(params)).await
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
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
    let (base, fetches) = hanging_agent().await;
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
    let (base, _) = hanging_agent().await;
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
    let (base, _) = hanging_agent().await;
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
