// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7898 SESS.2b (D5): a legacy subscribe lands on the session the ledger
//! charged, not on whatever session the bucket holds by the time it is sent.

use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use parking_lot::Mutex;
use serde_json::{Value, json};

use super::*;

/// Records the session header each `resources/subscribe` carried.
async fn peer() -> (String, Arc<Mutex<Vec<Option<String>>>>) {
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::default();
    let log = Arc::clone(&seen);
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::post(
            move |headers: HeaderMap, axum::Json(frame): axum::Json<Value>| {
                let log = Arc::clone(&log);
                async move {
                    log.lock().push(
                        headers
                            .get("mcp-session-id")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                    );
                    axum::Json(json!({"jsonrpc": "2.0", "id": frame["id"], "result": {}}))
                }
            },
        ),
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

fn transport(url: &str) -> Arc<HttpTransport> {
    HttpTransport::new(
        url,
        std::collections::HashMap::new(),
        Duration::from_secs(5),
        true,
    )
    .expect("transport")
}

fn set_session(t: &HttpTransport, id: &str) {
    t.sessions.write().insert(String::new(), id.to_owned());
}

#[tokio::test]
async fn a_legacy_call_carries_the_pinned_session() {
    let (url, seen) = peer().await;
    let t = transport(&url);
    set_session(&t, "s1");
    let pin = t.legacy_pin();
    set_session(&t, "s2");
    let answer = Arc::clone(&t)
        .legacy_interest(pin, "file:///a", true)
        .await
        .expect("answered");
    assert!(answer.error.is_none());
    assert_eq!(seen.lock().as_slice(), [Some("s1".to_owned())]);
}

#[tokio::test]
async fn a_sessionless_pin_sends_no_session() {
    let (url, seen) = peer().await;
    let t = transport(&url);
    let pin = t.legacy_pin();
    set_session(&t, "s2");
    Arc::clone(&t)
        .legacy_interest(pin, "file:///a", false)
        .await
        .expect("answered");
    assert_eq!(seen.lock().as_slice(), [None]);
}

#[test]
fn pins_of_different_sessions_name_different_holders() {
    let t = transport("http://127.0.0.1:9/mcp");
    let none = t.legacy_pin().holder;
    set_session(&t, "s1");
    let s1 = t.legacy_pin().holder;
    set_session(&t, "s2");
    assert!(none != s1 && s1 != t.legacy_pin().holder);
}
