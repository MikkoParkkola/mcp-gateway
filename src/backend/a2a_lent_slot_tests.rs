// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An A2A backend whose identity binding is required is reached per user
//! only as that user: its per-user slot fetches the agent's card under the
//! credential the user's dispatch lends, and neither that fetch nor any
//! send carries the backend's static headers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use serde_json::{Value, json};

use super::Backend;
use super::slot_eviction_tests::{AUDIENCE, subscriber_credential};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};

const USER: &str = "u:alpha";
const STATIC_HEADER: &str = "x-static-credential";

/// One request the agent received: its path, its `Authorization`, and
/// whether it carried the static header.
#[derive(Debug, Clone)]
struct Seen {
    path: &'static str,
    authorization: String,
    static_header: bool,
}

fn seen(path: &'static str, headers: &HeaderMap) -> Seen {
    Seen {
        path,
        authorization: headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        static_header: headers.contains_key(STATIC_HEADER),
    }
}

/// An A2A 1.0 agent on loopback that records every request and answers each
/// `SendMessage` with a completed task.
async fn recording_agent() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let endpoint = format!("{base}/a2a");
    let log = Arc::new(Mutex::new(Vec::new()));
    let (card_log, rpc_log) = (Arc::clone(&log), Arc::clone(&log));
    let app = Router::new()
        .route(
            "/.well-known/agent-card.json",
            get(move |headers: HeaderMap| {
                card_log.lock().unwrap().push(seen("card", &headers));
                let endpoint = endpoint.clone();
                async move {
                    axum::Json(json!({"name": "recording", "supportedInterfaces": [
                        {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]}))
                }
            }),
        )
        .route(
            "/a2a",
            post(move |headers: HeaderMap, axum::Json(body): axum::Json<Value>| {
                rpc_log.lock().unwrap().push(seen("rpc", &headers));
                async move {
                    axum::Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"task": {
                        "id": "t-1", "contextId": "c-1",
                        "status": {"state": "TASK_STATE_COMPLETED", "message": {
                            "messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "done"}]}}}}}))
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, log)
}

/// An A2A backend at `base` with a static credential header and a required
/// identity binding.
fn required_a2a_backend(base: &str) -> Arc<Backend> {
    let mut headers = HashMap::new();
    headers.insert(STATIC_HEADER.to_string(), "gateway-owned".to_string());
    Arc::new(Backend::new(
        "a2a-lent",
        BackendConfig {
            transport: TransportConfig::A2a {
                a2a_url: base.to_string(),
                a2a_agent_card_path: None,
            },
            headers,
            timeout: Duration::from_secs(10),
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: AUDIENCE.to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// START.6 (A2A): the user's first call starts their slot. The card fetch
/// goes out under the user's credential, and no request carries the
/// backend's static header.
#[tokio::test]
async fn an_a2a_per_user_slot_is_reached_only_as_its_user() {
    let (base, log) = recording_agent().await;
    let backend = required_a2a_backend(&base);
    let credential = subscriber_credential(USER);
    let bearer = credential[0].1.clone();

    let _ = backend
        .request_with_headers(
            "tools/call",
            Some(json!({"name": crate::a2a::translator::TOOL_NAME,
                "arguments": {"message": "hi"}})),
            &credential,
            Some(USER),
        )
        .await;

    let log = log.lock().unwrap().clone();
    assert!(
        log.iter().any(|s| s.path == "card") && log.iter().any(|s| s.path == "rpc"),
        "premise: the slot fetched the card and the call reached the agent: {log:?}"
    );
    let carried: Vec<_> = log.iter().filter(|s| s.static_header).collect();
    assert!(
        carried.is_empty(),
        "a per-user request carried the backend's static header: {carried:?}"
    );
    let not_as_user: Vec<_> = log.iter().filter(|s| s.authorization != bearer).collect();
    assert!(
        not_as_user.is_empty(),
        "a per-user request reached the agent other than as its user: {not_as_user:?}"
    );
}
