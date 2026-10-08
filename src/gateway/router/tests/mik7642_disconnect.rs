// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7642.PR.B` C2: a client that closes its connection mid-call on the
//! direct route cancels the call on a legacy HTTP backend, once, by the id
//! the backend received. Real sockets on both sides.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use crate::backend::Backend;
use crate::config::{AuthConfig, BackendConfig, FailsafeConfig};
use crate::transport::HttpTransport;

/// Every message the backend received, in arrival order.
type Seen = Arc<Mutex<Vec<Value>>>;

/// A legacy backend that answers `tools/call` only after a long sleep.
async fn slow_backend() -> (String, Seen) {
    let seen = Seen::default();
    let record = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |body: String| {
        let record = Arc::clone(&record);
        async move {
            let message: Value = serde_json::from_str(&body).unwrap_or_default();
            record.lock().unwrap().push(message.clone());
            let Some(id) = message.get("id").cloned() else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match message["method"].as_str() {
                Some("tools/list") => json!({"tools": [
                    {"name": "act", "description": "slow", "inputSchema": {"type": "object"}},
                ]}),
                Some("tools/call") => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    json!({"content": [{"type": "text", "text": "done"}]})
                }
                _ => json!({}),
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}/mcp"), seen)
}

fn of_method(seen: &Seen, method: &str) -> Vec<Value> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|m| m["method"] == method)
        .cloned()
        .collect()
}

#[tokio::test]
async fn a_client_disconnect_mid_call_cancels_the_backend_call_by_its_id() {
    let (backend_url, seen) = slow_backend().await;
    let (state, _store) = super::test_router_app_state_with_auth(&AuthConfig::default()).await;
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = HttpTransport::new(&backend_url, HashMap::new(), Duration::from_secs(30), true)
        .expect("a transport");
    backend.set_transport_for_test(transport as Arc<dyn crate::transport::Transport>);
    assert!(state.backends.register(backend));
    let router = super::create_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .expect("a client");
    let call = json!({
        "jsonrpc": "2.0", "id": "client-7", "method": "tools/call",
        "params": {"name": "act", "arguments": {}},
    });
    // Dropping the send closes the connection while the backend still works.
    let dropped = tokio::time::timeout(
        Duration::from_millis(1500),
        client
            .post(format!("http://{gateway}/mcp/svc"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(call.to_string())
            .send(),
    )
    .await;
    assert!(dropped.is_err(), "precondition: the call was still running");
    let calls = of_method(&seen, "tools/call");
    assert_eq!(calls.len(), 1, "precondition: the backend got the call");

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let cancels = of_method(&seen, "notifications/cancelled");
    assert_eq!(cancels.len(), 1, "exactly one cancel: {cancels:?}");
    assert_eq!(
        cancels[0]["params"]["requestId"], calls[0]["id"],
        "it names the backend's own id"
    );
    assert_ne!(cancels[0]["params"]["requestId"], json!("client-7"));
}
