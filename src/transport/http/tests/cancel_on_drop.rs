// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7642.PR.B`: a legacy exchange dropped before its reply was read sends
//! the backend one `notifications/cancelled` naming the id it received; an
//! answered request, `initialize`, and a modern exchange send none.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use crate::protocol::era::Era;
use crate::protocol::{JsonRpcRequest, RequestId};

/// The backend answers `slow` and `initialize` only after this.
const SLOW: Duration = Duration::from_secs(4);
/// How long a row watches for a cancel that must NOT arrive, or for a second
/// one after the first. An absence has no event to wait for.
const QUIET: Duration = Duration::from_millis(1500);

/// Every message the backend received, with its `MCP-Session-Id`.
type Seen = Arc<Mutex<Vec<(Value, Option<String>)>>>;

/// Woken each time the backend records a message, so a row waits for what it
/// needs (a request in flight, a cancel) instead of for a clock.
type Arrived = Arc<tokio::sync::Notify>;

async fn backend() -> (String, Seen, Arrived) {
    let seen = Seen::default();
    let arrived = Arrived::default();
    let (record, wake) = (Arc::clone(&seen), Arc::clone(&arrived));
    let app = axum::Router::new().fallback(move |headers: HeaderMap, body: String| {
        let (record, wake) = (Arc::clone(&record), Arc::clone(&wake));
        async move {
            let message: Value = serde_json::from_str(&body).unwrap_or_default();
            let session = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            record.lock().unwrap().push((message.clone(), session));
            wake.notify_one();
            let Some(id) = message.get("id").cloned() else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            if matches!(message["method"].as_str(), Some("slow" | "initialize")) {
                tokio::time::sleep(SLOW).await;
            }
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {}})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}/mcp"), seen, arrived)
}

fn request(id: i64, method: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(id),
        method: method.to_string(),
        params: None,
    }
}

/// How a row's exchange ends.
#[derive(Clone, Copy)]
enum Exchange {
    /// The caller gives up as soon as the backend has recorded the request.
    DroppedOnceReceived,
    /// The caller waits for the answer.
    Answered,
}

/// The messages of `method` the backend has recorded.
fn count(seen: &Seen, method: &str) -> usize {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(m, _)| m["method"] == method)
        .count()
}

/// Wait until the backend has recorded `wanted` messages of `method`.
async fn backend_has(seen: &Seen, arrived: &Arrived, method: &str, wanted: usize) {
    crate::test_pause::within(method, async {
        while count(seen, method) < wanted {
            arrived.notified().await;
        }
    })
    .await;
}

/// Send `request` shaped for `era` on `transport` and end the exchange as
/// `exchange` says. A dropped exchange is dropped the moment the backend has
/// the request, however long that took: the backend answers `slow` and
/// `initialize` only after [`SLOW`], so the drop always comes first.
async fn run_exchange(
    transport: &super::HttpTransport,
    (seen, arrived): (&Seen, &Arrived),
    request: &JsonRpcRequest,
    identity: Option<&str>,
    (era, exchange): (Option<Era>, Exchange),
) {
    let send = transport.send_request_with_headers(request, &[], identity, era);
    match exchange {
        Exchange::Answered => {
            let answer = crate::test_pause::within("the answer", send).await;
            assert!(answer.is_ok(), "the backend answers: {answer:?}");
        }
        Exchange::DroppedOnceReceived => {
            tokio::select! {
                answer = send => panic!("answered before it was dropped: {answer:?}"),
                () = backend_has(seen, arrived, &request.method, 1) => {}
            }
        }
    }
}

/// Run `request` as `exchange` says, then return the cancels that arrived
/// within [`QUIET`] of the end of the exchange.
async fn cancels_after(
    url: &str,
    (seen, arrived): (&Seen, &Arrived),
    request: &JsonRpcRequest,
    (era, exchange): (Option<Era>, Exchange),
) -> Vec<(Value, Option<String>)> {
    let transport = super::make_transport(url);
    super::set_default_session(&transport, "session-a");
    run_exchange(
        &transport,
        (seen, arrived),
        request,
        None,
        (era, exchange),
    )
    .await;
    cancels_within_quiet(seen).await
}

/// The cancels the backend has recorded after [`QUIET`] more: an absence has
/// no event to wait for, so the window is the observation.
async fn cancels_within_quiet(seen: &Seen) -> Vec<(Value, Option<String>)> {
    // timing: absence
    tokio::time::sleep(QUIET).await;
    seen.lock()
        .unwrap()
        .iter()
        .filter(|(m, _)| m["method"] == "notifications/cancelled")
        .cloned()
        .collect()
}

/// Whether the backend received `method`: a row that expects no cancel must
/// first show the request was in flight, or it passes for nothing sent.
fn received(seen: &Seen, method: &str) -> bool {
    count(seen, method) > 0
}

#[tokio::test]
async fn a_dropped_legacy_request_is_cancelled_once_by_its_own_id() {
    let (url, seen, arrived) = backend().await;
    let transport = super::make_transport(&url);
    super::set_default_session(&transport, "session-a");
    run_exchange(
        &transport,
        (&seen, &arrived),
        &request(41, "slow"),
        None,
        (None, Exchange::DroppedOnceReceived),
    )
    .await;
    // The cancel is an event to wait for; only a second one is an absence.
    backend_has(&seen, &arrived, "notifications/cancelled", 1).await;
    let cancels = cancels_within_quiet(&seen).await;
    assert_eq!(cancels.len(), 1, "exactly one cancel: {cancels:?}");
    let (cancel, session) = &cancels[0];
    assert_eq!(cancel["params"]["requestId"], json!(41), "{cancel}");
    assert!(cancel.get("id").is_none(), "a notification: {cancel}");
    assert_eq!(
        session.as_deref(),
        Some("session-a"),
        "the cancel rides the request's session"
    );
}

#[tokio::test]
async fn an_answered_request_is_never_cancelled() {
    let (url, seen, arrived) = backend().await;
    let cancels = cancels_after(
        &url,
        (&seen, &arrived),
        &request(42, "fast"),
        (None, Exchange::Answered),
    )
    .await;
    assert!(cancels.is_empty(), "{cancels:?}");
}

#[tokio::test]
async fn a_dropped_initialize_is_never_cancelled() {
    let (url, seen, arrived) = backend().await;
    let cancels = cancels_after(
        &url,
        (&seen, &arrived),
        &request(43, "initialize"),
        (None, Exchange::DroppedOnceReceived),
    )
    .await;
    assert!(received(&seen, "initialize"), "precondition: it was sent");
    assert!(cancels.is_empty(), "{cancels:?}");
}

/// Dropping the POST closes a modern backend's stream, which is its cancel.
#[tokio::test]
async fn a_dropped_modern_request_sends_no_notification() {
    let (url, seen, arrived) = backend().await;
    let cancels = cancels_after(
        &url,
        (&seen, &arrived),
        &request(44, "slow"),
        (Some(Era::Modern), Exchange::DroppedOnceReceived),
    )
    .await;
    assert!(received(&seen, "slow"), "precondition: it was sent");
    assert!(cancels.is_empty(), "{cancels:?}");
}

/// R1: the session-recovery resend is its own exchange. Its first POST was
/// answered (session not found), so only the resend, dropped mid-call, is
/// cancelled: once, on the fresh session.
#[tokio::test]
async fn a_dropped_recovery_resend_is_cancelled_once_on_the_fresh_session() {
    use crate::transport::Transport as _;
    let seen = Seen::default();
    let arrived = Arrived::default();
    let (record, wake) = (Arc::clone(&seen), Arc::clone(&arrived));
    let app = axum::Router::new().fallback(move |headers: HeaderMap, body: String| {
        let (record, wake) = (Arc::clone(&record), Arc::clone(&wake));
        async move {
            let message: Value = serde_json::from_str(&body).unwrap_or_default();
            let session = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            record
                .lock()
                .unwrap()
                .push((message.clone(), session.clone()));
            wake.notify_one();
            let Some(id) = message.get("id").cloned() else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            if message["method"] == "initialize" {
                let body = json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                    "capabilities": {}, "serverInfo": {"name": "r1", "version": "0"}}});
                return ([("mcp-session-id", "fresh")], axum::Json(body)).into_response();
            }
            if session.as_deref() != Some("fresh") {
                let body = json!({"jsonrpc": "2.0", "id": id,
                    "error": {"code": -32015, "message": "Session not found"}});
                return axum::Json(body).into_response();
            }
            tokio::time::sleep(SLOW).await;
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}})).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let transport = super::make_transport(&format!("http://{addr}/mcp"));
    super::set_default_session(&transport, "stale");
    // The resend is the second `tools/list` the backend records; drop the
    // call there, however long the recovery took.
    let call = transport.request("tools/list", None);
    tokio::select! {
        answer = call => panic!("answered before it was dropped: {answer:?}"),
        () = backend_has(&seen, &arrived, "tools/list", 2) => {}
    }
    backend_has(&seen, &arrived, "notifications/cancelled", 1).await;
    // timing: absence
    tokio::time::sleep(QUIET).await;

    let messages = seen.lock().unwrap().clone();
    let lists: Vec<_> = messages
        .iter()
        .filter(|(m, _)| m["method"] == "tools/list")
        .collect();
    assert_eq!(
        lists.len(),
        2,
        "precondition: the call was resent: {messages:?}"
    );
    let cancels: Vec<_> = messages
        .iter()
        .filter(|(m, _)| m["method"] == "notifications/cancelled")
        .collect();
    assert_eq!(cancels.len(), 1, "exactly one cancel: {messages:?}");
    assert_eq!(cancels[0].0["params"]["requestId"], lists[1].0["id"]);
    assert_eq!(
        cancels[0].1.as_deref(),
        Some("fresh"),
        "on the fresh session"
    );
}

/// The cancel rides the caller's own session bucket, never the shared one: a
/// stateful backend sees it on the same session as the request.
#[tokio::test]
async fn the_cancel_carries_the_callers_identity() {
    let (url, seen, arrived) = backend().await;
    let transport = super::make_transport(&url);
    super::set_default_session(&transport, "shared-session");
    transport
        .sessions
        .write()
        .insert("alice".to_string(), "alice-session".to_string());
    run_exchange(
        &transport,
        (&seen, &arrived),
        &request(45, "slow"),
        Some("alice"),
        (None, Exchange::DroppedOnceReceived),
    )
    .await;
    backend_has(&seen, &arrived, "notifications/cancelled", 1).await;
    let cancels: Vec<_> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, _)| m["method"] == "notifications/cancelled")
        .cloned()
        .collect();
    assert_eq!(cancels.len(), 1, "{cancels:?}");
    assert_eq!(
        cancels[0].1.as_deref(),
        Some("alice-session"),
        "alice's session"
    );
}
