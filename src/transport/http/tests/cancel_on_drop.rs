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
/// How long a caller waits before dropping the exchange.
const PATIENCE: Duration = Duration::from_millis(300);
/// How long a cancel has to arrive.
const ARRIVAL: Duration = Duration::from_millis(1500);

/// Every message the backend received, with its `MCP-Session-Id`.
type Seen = Arc<Mutex<Vec<(Value, Option<String>)>>>;

async fn backend() -> (String, Seen) {
    let seen = Seen::default();
    let record = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |headers: HeaderMap, body: String| {
        let record = Arc::clone(&record);
        async move {
            let message: Value = serde_json::from_str(&body).unwrap_or_default();
            let session = headers
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            record.lock().unwrap().push((message.clone(), session));
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
    (format!("http://{addr}/mcp"), seen)
}

fn request(id: i64, method: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(id),
        method: method.to_string(),
        params: None,
    }
}

/// Send `request` shaped for `era`, give up after [`PATIENCE`] (dropping the
/// exchange if it has not finished), then return the cancels that arrived.
async fn cancels_after(
    url: &str,
    seen: &Seen,
    request: &JsonRpcRequest,
    era: Option<Era>,
) -> Vec<(Value, Option<String>)> {
    let transport = super::make_transport(url);
    super::set_default_session(&transport, "session-a");
    let _ = tokio::time::timeout(
        PATIENCE,
        transport.send_request_with_headers(request, &[], None, era),
    )
    .await;
    tokio::time::sleep(ARRIVAL).await;
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
    seen.lock()
        .unwrap()
        .iter()
        .any(|(m, _)| m["method"] == method)
}

#[tokio::test]
async fn a_dropped_legacy_request_is_cancelled_once_by_its_own_id() {
    let (url, seen) = backend().await;
    let cancels = cancels_after(&url, &seen, &request(41, "slow"), None).await;
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
    let (url, seen) = backend().await;
    let cancels = cancels_after(&url, &seen, &request(42, "fast"), None).await;
    assert!(cancels.is_empty(), "{cancels:?}");
}

#[tokio::test]
async fn a_dropped_initialize_is_never_cancelled() {
    let (url, seen) = backend().await;
    let cancels = cancels_after(&url, &seen, &request(43, "initialize"), None).await;
    assert!(received(&seen, "initialize"), "precondition: it was sent");
    assert!(cancels.is_empty(), "{cancels:?}");
}

/// Dropping the POST closes a modern backend's stream, which is its cancel.
#[tokio::test]
async fn a_dropped_modern_request_sends_no_notification() {
    let (url, seen) = backend().await;
    let cancels = cancels_after(&url, &seen, &request(44, "slow"), Some(Era::Modern)).await;
    assert!(received(&seen, "slow"), "precondition: it was sent");
    assert!(cancels.is_empty(), "{cancels:?}");
}
