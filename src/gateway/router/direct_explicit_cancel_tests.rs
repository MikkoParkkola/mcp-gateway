// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7642 PR.C, C4/D5 on the direct route: a client's explicit cancel aborts
//! only its own in-flight call, and the backend is cancelled by the id it saw.
//!
//! The upstream is a 2025-era HTTP server: it holds every `tools/call` (and
//! a `tools/list` once `hold_list` is set) until the test releases it, and records the backend-side id of each call and the
//! `requestId` of each `notifications/cancelled` it receives (PR.B's guard
//! sends that, with the backend's own id, when a dispatch is dropped).
use super::create_router;
use super::tests::direct_route_state_with_identity;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::key_server::oidc::VerifiedIdentity;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};
use tower::ServiceExt;

struct Upstream {
    /// The backend-side id of every `tools/call`, in arrival order.
    calls: parking_lot::Mutex<Vec<Value>>,
    /// The `requestId` of every `notifications/cancelled`.
    cancels: parking_lot::Mutex<Vec<Value>>,
    arrived: tokio::sync::Notify,
    cancelled: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    /// Hold `tools/list` like a call; off by default, so the fixture's own
    /// catalogue reads answer at once.
    hold_list: std::sync::atomic::AtomicBool,
}

async fn upstream() -> (String, Arc<Upstream>) {
    let seen = Arc::new(Upstream {
        calls: parking_lot::Mutex::default(),
        cancels: parking_lot::Mutex::default(),
        arrived: tokio::sync::Notify::new(),
        cancelled: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
        hold_list: std::sync::atomic::AtomicBool::new(false),
    });
    let peer = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let peer = Arc::clone(&peer);
        async move {
            let method = message["method"].as_str().unwrap_or_default().to_owned();
            if method == "notifications/cancelled" {
                peer.cancels
                    .lock()
                    .push(message["params"]["requestId"].clone());
                peer.cancelled.notify_one();
            }
            let Some(id) = message.get("id").cloned() else {
                return StatusCode::ACCEPTED.into_response();
            };
            let result = match method.as_str() {
                "initialize" => json!({
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ledger", "version": "0" }
                }),
                "tools/list" => {
                    if peer.hold_list.load(std::sync::atomic::Ordering::SeqCst) {
                        peer.calls.lock().push(id.clone());
                        peer.arrived.notify_one();
                        peer.release.acquire().await.expect("open").forget();
                    }
                    json!({ "tools": [{
                        "name": "slow", "description": "d", "inputSchema": { "type": "object" }
                    }] })
                }
                "tools/call" => {
                    peer.calls.lock().push(id.clone());
                    peer.arrived.notify_one();
                    peer.release
                        .acquire()
                        .await
                        .expect("the release gate stays open")
                        .forget();
                    json!({ "content": [{ "type": "text", "text": "done" }] })
                }
                _ => json!({}),
            };
            axum::Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, seen)
}

struct Gateway {
    router: axum::Router,
    upstream: Arc<Upstream>,
    _store: tempfile::TempDir,
}

async fn gateway() -> Gateway {
    let (url, upstream) = upstream().await;
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(30),
    ));
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    Gateway {
        router: create_router(state),
        upstream,
        _store: store,
    }
}

/// POST `message` to the direct route as `subject`.
async fn send(gw: &Gateway, message: Value, subject: &str) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(message.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: subject.to_owned(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_owned(),
    });
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn call(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": "slow", "arguments": {} } })
}

fn cancel(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": id, "reason": "changed my mind" } })
}

/// Start `subject`'s call `id` and wait until the backend holds it.
async fn held_call(
    gw: &Arc<Gateway>,
    id: i64,
    subject: &'static str,
) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let started = {
        let gw = Arc::clone(gw);
        tokio::spawn(async move { send(&gw, call(id), subject).await })
    };
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.arrived.notified())
        .await
        .expect("the backend holds the call");
    started
}

/// C4: the caller's own cancel of its call reaches the backend once, naming
/// the id the backend saw (never the client's), and the client is answered
/// -32800 with HTTP 200, as on `/mcp`: its own choice, not a failure.
/// Mutants: the cancel lookup removed (no send); the client id forwarded
/// instead (a wrong `requestId`); the own-cancel answer removed (a 500).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_callers_own_cancel_reaches_the_backend_by_its_own_id() {
    let gw = Arc::new(gateway().await);
    let pending = held_call(&gw, 7, "alpha").await;
    assert_eq!(send(&gw, cancel(7), "alpha").await.0, StatusCode::ACCEPTED);
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.cancelled.notified())
        .await
        .expect("the backend receives a cancel");
    let (status, answer) = pending.await.expect("the call task joins");
    assert_eq!(answer["error"]["code"], json!(-32800), "{answer}");
    assert_eq!(status, StatusCode::OK, "{answer}");
    let backend_id = gw.upstream.calls.lock()[0].clone();
    assert_eq!(*gw.upstream.cancels.lock(), vec![backend_id]);
}

/// A direct `tools/list` drains the backend's catalogue outside the call arm;
/// the caller's own cancel aborts it too. Mutant: the drain not abortable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_callers_own_cancel_stops_its_catalogue_read() {
    let gw = Arc::new(gateway().await);
    gw.upstream
        .hold_list
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let list = json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" });
    let pending = {
        let gw = Arc::clone(&gw);
        tokio::spawn(async move { send(&gw, list, "alpha").await })
    };
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.arrived.notified())
        .await
        .expect("the backend holds the listing");
    assert_eq!(send(&gw, cancel(9), "alpha").await.0, StatusCode::ACCEPTED);
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.cancelled.notified())
        .await
        .expect("the backend receives a cancel");
    let (status, answer) = pending.await.expect("the listing task joins");
    assert_eq!(answer["error"]["code"], json!(-32800), "{answer}");
    assert_eq!(status, StatusCode::OK, "{answer}");
}

/// C4 (MIK-8072 kept): another caller naming the same client id cancels
/// nothing; the call completes and the backend is sent no cancel. Mutant:
/// the owner dropped from the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_callers_cancel_of_the_same_id_reaches_nothing() {
    let gw = Arc::new(gateway().await);
    let pending = held_call(&gw, 7, "alpha").await;
    assert_eq!(send(&gw, cancel(7), "beta").await.0, StatusCode::ACCEPTED);
    gw.upstream.release.add_permits(1);
    let (status, answer) = pending.await.expect("the call task joins");
    assert_eq!(status, StatusCode::OK);
    assert!(
        answer.get("error").is_none(),
        "alpha's call completes: {answer}"
    );
    assert!(
        gw.upstream.cancels.lock().is_empty(),
        "nothing was cancelled"
    );
}

/// D5: a second call reusing a live id is not registered, so the caller's
/// cancel aborts the first only, and the second still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_live_id_leaves_the_first_call_cancellable() {
    let gw = Arc::new(gateway().await);
    let first = held_call(&gw, 7, "alpha").await;
    let second = held_call(&gw, 7, "alpha").await;
    assert_eq!(send(&gw, cancel(7), "alpha").await.0, StatusCode::ACCEPTED);
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.cancelled.notified())
        .await
        .expect("the backend receives a cancel");
    let (_, first) = first.await.expect("the first call joins");
    assert_eq!(first["error"]["code"], json!(-32800), "{first}");
    // Two: the aborted first call's handler is still parked upstream too.
    gw.upstream.release.add_permits(2);
    let (_, second) = second.await.expect("the second call joins");
    assert!(
        second.get("error").is_none(),
        "the duplicate completes: {second}"
    );
    let first_backend_id = gw.upstream.calls.lock()[0].clone();
    assert_eq!(*gw.upstream.cancels.lock(), vec![first_backend_id]);
}

/// POST `message` to `/mcp` as `subject` on `session`; the answer and the
/// session the gateway names.
async fn send_mcp(
    gw: &Gateway,
    message: Value,
    subject: &str,
    session: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let mut request = builder
        .body(axum::body::Body::from(message.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: subject.to_owned(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_owned(),
    });
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body, session)
}

/// `subject`'s own session on `/mcp`.
async fn mcp_session(gw: &Gateway, subject: &str) -> String {
    let init = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": crate::protocol::PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": { "name": "c5", "version": "0" } } });
    let (status, answer, session) = send_mcp(gw, init, subject, None).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    session.expect("the gateway names a session")
}

fn invoke(id: i64) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": { "server": "ledger", "tool": "slow", "arguments": {} } } })
}

/// Start `subject`'s `/mcp` call `id` on `session`; wait until the backend
/// holds it.
async fn held_mcp_call(
    gw: &Arc<Gateway>,
    id: i64,
    subject: &'static str,
    session: &str,
) -> tokio::task::JoinHandle<(StatusCode, Value, Option<String>)> {
    let started = {
        let gw = Arc::clone(gw);
        let session = session.to_owned();
        tokio::spawn(async move { send_mcp(&gw, invoke(id), subject, Some(&session)).await })
    };
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.arrived.notified())
        .await
        .expect("the backend holds the call");
    started
}

/// C5: on `/mcp` the caller's own cancel, on its own session, reaches the
/// backend once by the backend's id, and the call is answered -32800.
/// Mutant: the `/mcp` cancel lookup removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_mcp_callers_own_cancel_reaches_the_backend_by_its_own_id() {
    let gw = Arc::new(gateway().await);
    let session = mcp_session(&gw, "alpha").await;
    let pending = held_mcp_call(&gw, 7, "alpha", &session).await;
    let (status, _, _) = send_mcp(&gw, cancel(7), "alpha", Some(&session)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    tokio::time::timeout(Duration::from_secs(30), gw.upstream.cancelled.notified())
        .await
        .expect("the backend receives a cancel");
    let (_, answer, _) = pending.await.expect("the call task joins");
    assert_eq!(answer["error"]["code"], json!(-32800), "{answer}");
    let backend_id = gw.upstream.calls.lock()[0].clone();
    assert_eq!(*gw.upstream.cancels.lock(), vec![backend_id]);
}

/// C5: another caller, on its own session, naming the same id cancels
/// nothing; the call completes. Mutants: the owner or the session dropped
/// from the key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_mcp_callers_cancel_of_the_same_id_reaches_nothing() {
    let gw = Arc::new(gateway().await);
    let alpha = mcp_session(&gw, "alpha").await;
    let beta = mcp_session(&gw, "beta").await;
    let pending = held_mcp_call(&gw, 7, "alpha", &alpha).await;
    let (status, _, _) = send_mcp(&gw, cancel(7), "beta", Some(&beta)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    gw.upstream.release.add_permits(1);
    let (_, answer, _) = pending.await.expect("the call task joins");
    assert!(
        answer.get("error").is_none(),
        "alpha's call completes: {answer}"
    );
    assert!(
        gw.upstream.cancels.lock().is_empty(),
        "nothing was cancelled"
    );
}

/// C5: the same caller on another of its sessions names the same id and
/// cancels nothing: the session is part of the key. Mutant: the session
/// dropped from the `/mcp` key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_mcp_caller_on_another_session_reaches_nothing() {
    let gw = Arc::new(gateway().await);
    let first = mcp_session(&gw, "alpha").await;
    let second = mcp_session(&gw, "alpha").await;
    assert_ne!(first, second, "two sessions");
    let pending = held_mcp_call(&gw, 7, "alpha", &first).await;
    let (status, _, _) = send_mcp(&gw, cancel(7), "alpha", Some(&second)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    gw.upstream.release.add_permits(1);
    let (_, answer, _) = pending.await.expect("the call task joins");
    assert!(
        answer.get("error").is_none(),
        "the first session's call completes: {answer}"
    );
    assert!(
        gw.upstream.cancels.lock().is_empty(),
        "nothing was cancelled"
    );
}
