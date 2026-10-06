// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7898 SESS.1: a 404 on a stream open drops the session it carried and
//! re-handshakes, as the request path does for a request.

use std::sync::Arc;
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use serde_json::{Value, json};

use super::*;

/// Answers `initialize` with session `s2`, a notification with 202, and
/// every stream open (listen POST, session GET) with 404.
async fn peer() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let (post_seen, get_seen) = (Arc::clone(&seen), Arc::clone(&seen));
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(move |axum::Json(frame): axum::Json<Value>| {
            let seen = Arc::clone(&post_seen);
            async move { answer(&seen, &frame) }
        })
        .get(move || {
            let seen = Arc::clone(&get_seen);
            async move {
                seen.lock().push("GET".to_owned());
                axum::http::StatusCode::NOT_FOUND
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen)
}

fn answer(seen: &Mutex<Vec<String>>, frame: &Value) -> Response {
    let method = frame["method"].as_str().unwrap_or_default().to_owned();
    seen.lock().push(method.clone());
    let Some(id) = frame.get("id") else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    if method != "initialize" {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    let mut response = axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "serverInfo": {"name": "peer", "version": "0"}}}))
    .into_response();
    response
        .headers_mut()
        .insert("mcp-session-id", "s2".parse().expect("header"));
    response
}

fn transport(url: &str) -> Arc<HttpTransport> {
    HttpTransport::new(
        url,
        std::collections::HashMap::new(),
        Duration::from_secs(5),
        true,
    )
    .expect("transport")
}

fn session(t: &HttpTransport) -> Option<String> {
    t.sessions
        .read()
        .get(HttpTransport::bucket_key(None))
        .cloned()
}

fn initializes(seen: &Mutex<Vec<String>>) -> usize {
    seen.lock().iter().filter(|m| *m == "initialize").count()
}

/// The 404 carried the current session: it is dropped and a new one is
/// handshaken, which the next open carries.
#[tokio::test]
async fn a_404_on_the_session_stream_heals_the_session() {
    let (url, seen) = peer().await;
    let t = transport(&url);
    t.sessions.write().insert(String::new(), "s1".to_owned());
    let opened = t
        .open_session_stream(Watched::default())
        .await
        .expect("sent");
    assert!(matches!(opened, Err(404)));
    assert_eq!(initializes(&seen), 1);
    assert_eq!(session(&t).as_deref(), Some("s2"));
}

/// A late 404 from an older session leaves the newer one, and runs no
/// second handshake.
#[tokio::test]
async fn a_late_404_from_an_old_session_keeps_the_new_one() {
    let (url, seen) = peer().await;
    let t = transport(&url);
    t.sessions.write().insert(String::new(), "s2".to_owned());
    assert_eq!(t.refused(404, Some("s1".to_owned())).await, 404);
    assert_eq!(initializes(&seen), 0);
    assert_eq!(session(&t).as_deref(), Some("s2"));
}

/// A sessionless 404 is not an expired session: nothing is handshaken.
#[tokio::test]
async fn a_sessionless_404_runs_no_handshake() {
    let (url, seen) = peer().await;
    let t = transport(&url);
    let opened = t.open_listen(Requested::default()).await.expect("sent");
    assert!(matches!(opened, Err(404)));
    assert_eq!(initializes(&seen), 0);
}
