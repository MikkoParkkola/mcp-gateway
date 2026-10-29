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
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::transport::HttpTransport;

/// Every message the backend received, in arrival order.
type Seen = Arc<Mutex<Vec<Value>>>;

/// A legacy backend that answers `tools/call` after `call_delay`.
async fn slow_backend(call_delay: Duration) -> (String, Seen) {
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
                    tokio::time::sleep(call_delay).await;
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

/// Auth on with one shared key for every backend, as the direct route is
/// served in practice: a request it refuses would answer at once.
fn auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k")),
            expires_at: None,
            name: "c2-client".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        ..AuthConfig::default()
    }
}

#[tokio::test]
async fn a_client_disconnect_mid_call_cancels_the_backend_call_by_its_id() {
    // The backend holds the call far past the test's end: only the abort ends it.
    let (backend_url, seen) = slow_backend(Duration::from_secs(3600)).await;
    let (state, _store) = super::test_router_app_state_with_auth(&auth()).await;
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    // The transport timeout must outlast the test's own hang guard.
    let transport = HttpTransport::new(
        &backend_url,
        HashMap::new(),
        Duration::from_secs(3600),
        true,
    )
    .expect("a transport");
    // A transport that never handshook reads as not connected, and the
    // backend would then restart from its empty config instead of using it.
    transport
        .initialize()
        .await
        .expect("the backend handshakes");
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
    // Aborting the task drops the in-flight request while the backend still
    // works; with no idle pool the connection closes.
    let task_client = client.clone();
    let task = tokio::spawn(async move {
        let response = task_client
            .post(format!("http://{gateway}/mcp/svc"))
            .header("authorization", "Bearer k")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(call.to_string())
            .send()
            .await?;
        let status = response.status();
        Ok::<_, reqwest::Error>((status, response.text().await?))
    });
    until_seen(&seen, "tools/call", "the backend receives the call").await;
    assert!(
        !task.is_finished(),
        "precondition: the call was still running"
    );
    task.abort();
    let joined = task.await;
    assert!(
        joined
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "precondition: the aborted call was cancelled, not finished: {joined:?}"
    );
    let calls = of_method(&seen, "tools/call");
    assert_eq!(
        calls.len(),
        1,
        "precondition: the backend got the call: {:?}",
        seen.lock().unwrap()
    );

    until_seen(&seen, "notifications/cancelled", "the cancel arrives").await;
    // timing: absence
    tokio::time::sleep(Duration::from_millis(500)).await;
    let cancels = of_method(&seen, "notifications/cancelled");
    assert_eq!(cancels.len(), 1, "exactly one cancel: {cancels:?}");
    assert_eq!(
        cancels[0]["params"]["requestId"], calls[0]["id"],
        "it names the backend's own id"
    );
    assert_ne!(cancels[0]["params"]["requestId"], json!("client-7"));
}

/// MIK-8614.CANCELZERO.1: the "0 after completion" half of MIK-7642.GH2495.3
/// on this route. A client that disconnects after reading the answer sends
/// the backend no cancel: the exchange already finished, so there is nothing
/// left to cancel.
#[tokio::test]
async fn a_client_disconnect_after_the_answer_sends_no_cancel() {
    let (backend_url, seen) = slow_backend(Duration::ZERO).await;
    let (state, _store) = super::test_router_app_state_with_auth(&auth()).await;
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = HttpTransport::new(&backend_url, HashMap::new(), Duration::from_secs(30), true)
        .expect("a transport");
    // A transport that never handshook reads as not connected, and the
    // backend would then restart from its empty config instead of using it.
    transport
        .initialize()
        .await
        .expect("the backend handshakes");
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
    let exchange = async {
        let response = client
            .post(format!("http://{gateway}/mcp/svc"))
            .header("authorization", "Bearer k")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(call.to_string())
            .send()
            .await?;
        let status = response.status();
        Ok::<_, reqwest::Error>((status, response.text().await?))
    };
    // The backend answers at once; the bound is only a hang guard.
    let (status, body) = tokio::time::timeout(Duration::from_secs(30), exchange)
        .await
        .expect("the answered call arrives")
        .expect("the whole response reads");
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert!(body.contains("done"), "the client read the answer: {body}");
    // With no idle pool, dropping the client closes the connection.
    drop(client);
    // A wrongly sent cancel would arrive at once; give it time to show.
    // timing: absence
    tokio::time::sleep(Duration::from_secs(1)).await;
    let calls = of_method(&seen, "tools/call");
    assert_eq!(
        calls.len(),
        1,
        "MIK-8614.CANCELZERO.1: the backend got the call once: {:?}",
        seen.lock().unwrap()
    );
    let cancels = of_method(&seen, "notifications/cancelled");
    assert!(
        cancels.is_empty(),
        "MIK-8614.CANCELZERO.1: no cancel after completion: {cancels:?}"
    );
}

/// Wait, under a 10 s hang guard, until the backend has seen `method`.
async fn until_seen(seen: &Seen, method: &str, what: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while of_method(seen, method).is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(what);
}

/// Serve the gateway with the legacy `svc` backend over real sockets, and open
/// an `/mcp` session on it. The store keeps the task runtime alive.
async fn mcp_gateway_with_slow_backend(
    call_delay: Duration,
) -> (
    SocketAddr,
    Seen,
    reqwest::Client,
    String,
    crate::gateway::router::tests::FixtureDir,
) {
    let (backend_url, seen) = slow_backend(call_delay).await;
    let (state, store) = super::test_router_app_state_with_auth(&auth()).await;
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    // The transport timeout must outlast the test's own hang guard.
    let transport = HttpTransport::new(
        &backend_url,
        HashMap::new(),
        Duration::from_secs(3600),
        true,
    )
    .expect("a transport");
    // A transport that never handshook reads as not connected, and the
    // backend would then restart from its empty config instead of using it.
    transport
        .initialize()
        .await
        .expect("the backend handshakes");
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
    let session = mcp_session(&client, gateway).await;
    (gateway, seen, client, session, store)
}

/// Open an `/mcp` session over real sockets: `initialize` names the session,
/// then `notifications/initialized` completes the handshake.
async fn mcp_session(client: &reqwest::Client, gateway: SocketAddr) -> String {
    let init = json!({
        "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": crate::protocol::PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "c4", "version": "0"},
        },
    });
    let response = client
        .post(format!("http://{gateway}/mcp"))
        .header("authorization", "Bearer k")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(init.to_string())
        .send()
        .await
        .expect("initialize answers");
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("the gateway names a session")
        .to_str()
        .expect("an ASCII session id")
        .to_owned();
    let status = response.status();
    let body = response.text().await.expect("the handshake reads");
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert!(body.contains("protocolVersion"), "handshake: {body}");
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let status = client
        .post(format!("http://{gateway}/mcp"))
        .header("authorization", "Bearer k")
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("mcp-session-id", &session)
        .body(initialized.to_string())
        .send()
        .await
        .expect("initialized sends")
        .status();
    assert_eq!(status, reqwest::StatusCode::ACCEPTED);
    session
}

/// A `gateway_invoke` of the legacy backend's slow tool, as the client sends it.
fn invoke(client_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": client_id, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "svc", "tool": "act", "arguments": {}},
        },
    })
}

/// MIK-8614.CANCELZERO.4: the "1" row on the meta-MCP route. A client that
/// closes its `/mcp` connection mid-call cancels the backend call once, by the
/// id the backend received.
#[tokio::test]
async fn an_mcp_client_disconnect_mid_call_cancels_the_backend_call_by_its_id() {
    // The backend holds the call far past the test's end: only the abort ends it.
    let (gateway, seen, client, session, _store) =
        mcp_gateway_with_slow_backend(Duration::from_secs(3600)).await;
    let call = invoke("client-7");
    // Aborting the task drops the in-flight request while the backend still
    // works; with no idle pool the connection closes.
    let task_client = client.clone();
    let task_session = session.clone();
    let task = tokio::spawn(async move {
        let response = task_client
            .post(format!("http://{gateway}/mcp"))
            .header("authorization", "Bearer k")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-session-id", &task_session)
            .body(call.to_string())
            .send()
            .await?;
        let status = response.status();
        Ok::<_, reqwest::Error>((status, response.text().await?))
    });
    until_seen(&seen, "tools/call", "the backend receives the call").await;
    assert!(
        !task.is_finished(),
        "precondition: the call was still running"
    );
    task.abort();
    let joined = task.await;
    assert!(
        joined
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "precondition: the aborted call was cancelled, not finished: {joined:?}"
    );
    let calls = of_method(&seen, "tools/call");
    assert_eq!(
        calls.len(),
        1,
        "precondition: the backend got the call: {:?}",
        seen.lock().unwrap()
    );
    until_seen(&seen, "notifications/cancelled", "the cancel arrives").await;
    // timing: absence
    tokio::time::sleep(Duration::from_millis(500)).await;
    let calls = of_method(&seen, "tools/call");
    assert_eq!(
        calls.len(),
        1,
        "MIK-8614.CANCELZERO.4: the backend got the call once: {:?}",
        seen.lock().unwrap()
    );
    let cancels = of_method(&seen, "notifications/cancelled");
    assert_eq!(
        cancels.len(),
        1,
        "MIK-8614.CANCELZERO.4: exactly one cancel: {cancels:?}"
    );
    assert_eq!(
        cancels[0]["params"]["requestId"], calls[0]["id"],
        "it names the backend's own id"
    );
    assert_ne!(cancels[0]["params"]["requestId"], json!("client-7"));
}

/// MIK-8614.CANCELZERO.4: the "0 after completion" half on the meta-MCP route.
/// A client that disconnects after reading the answer sends no cancel.
#[tokio::test]
async fn an_mcp_client_disconnect_after_the_answer_sends_no_cancel() {
    let (gateway, seen, client, session, _store) =
        mcp_gateway_with_slow_backend(Duration::ZERO).await;
    let call = invoke("client-7");
    let exchange = async {
        let response = client
            .post(format!("http://{gateway}/mcp"))
            .header("authorization", "Bearer k")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("mcp-session-id", &session)
            .body(call.to_string())
            .send()
            .await?;
        let status = response.status();
        Ok::<_, reqwest::Error>((status, response.text().await?))
    };
    // The backend answers at once; the bound is only a hang guard.
    let (status, body) = tokio::time::timeout(Duration::from_secs(30), exchange)
        .await
        .expect("the answered call arrives")
        .expect("the whole response reads");
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert!(body.contains("done"), "the client read the answer: {body}");
    // With no idle pool, dropping the client closes the connection.
    drop(client);
    // A wrongly sent cancel would arrive at once; give it time to show.
    // timing: absence
    tokio::time::sleep(Duration::from_secs(1)).await;
    let calls = of_method(&seen, "tools/call");
    assert_eq!(
        calls.len(),
        1,
        "MIK-8614.CANCELZERO.4: the backend got the call once: {:?}",
        seen.lock().unwrap()
    );
    let cancels = of_method(&seen, "notifications/cancelled");
    assert!(
        cancels.is_empty(),
        "MIK-8614.CANCELZERO.4: no cancel after completion: {cancels:?}"
    );
}
