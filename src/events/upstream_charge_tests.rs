// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7898 SESS.2b (B06 PR-2 D5, option B): a legacy subscribe whose outcome
//! is uncertain stays charged against the backend's URI cap, across retries,
//! until a release point (config removal, restart).

use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use serde_json::{Value, json};

use super::UpstreamListeners;
use crate::backend::{Backend, BackendRegistry};
use crate::events::upstream_need::{Interest, MAX_URIS};

const URI_A: &str = "file:///a";

/// A legacy (2025-06-18) HTTP peer. The first `resources/subscribe` of
/// [`URI_A`] gets an HTTP 500: the peer may have acted on it, so whether it
/// holds the subscription is unknown. Later calls are answered.
#[derive(Clone, Default)]
struct Peer {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    held: Arc<Mutex<Vec<String>>>,
}

impl Peer {
    async fn start() -> (Self, String) {
        let peer = Self::default();
        let state = peer.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(frame): axum::Json<Value>| {
                let state = state.clone();
                async move { state.answer(&frame) }
            })
            .get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    axum::body::Body::from_stream(futures::stream::pending::<
                        Result<String, std::io::Error>,
                    >()),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind peer");
        let url = format!("http://{}/", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (peer, url)
    }

    fn answer(&self, frame: &Value) -> Response {
        let Some(id) = frame.get("id").cloned() else {
            return axum::http::StatusCode::ACCEPTED.into_response();
        };
        let method = frame["method"].as_str().unwrap_or_default().to_owned();
        let uri = frame["params"]["uri"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let first_of_a = {
            let mut calls = self.calls.lock();
            calls.push((method.clone(), uri.clone()));
            method == "resources/subscribe"
                && uri == URI_A
                && calls
                    .iter()
                    .filter(|c| c.0 == method && c.1 == URI_A)
                    .count()
                    == 1
        };
        let reply = |result: Value| {
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
        };
        match method.as_str() {
            "initialize" => {
                let mut response = reply(json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"resources": {"subscribe": true, "listChanged": true}},
                    "serverInfo": {"name": "peer", "version": "0"},
                }));
                response
                    .headers_mut()
                    .insert("mcp-session-id", "charge-session".parse().expect("header"));
                response
            }
            "resources/subscribe" if first_of_a => {
                self.held.lock().push(uri);
                axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            "resources/subscribe" | "resources/unsubscribe" => {
                let mut held = self.held.lock();
                held.retain(|u| *u != uri);
                if method == "resources/subscribe" {
                    held.push(uri);
                }
                reply(json!({}))
            }
            "ping" => reply(json!({})),
            _ => axum::Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}
            }))
            .into_response(),
        }
    }

    fn subscribes_of(&self, uri: &str) -> usize {
        self.calls
            .lock()
            .iter()
            .filter(|c| c.0 == "resources/subscribe" && c.1 == uri)
            .count()
    }

    /// Wait, bounded, until `done` holds.
    async fn until(&self, what: &str, done: impl Fn(&Self) -> bool) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !done(self) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("peer never saw: {what}"));
    }
}

fn listeners_for(url: &str) -> Arc<UpstreamListeners> {
    let registry = Arc::new(BackendRegistry::new());
    let config = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: url.to_owned(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ..crate::config::BackendConfig::default()
    };
    assert!(registry.register(Arc::new(Backend::new(
        "b",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))));
    UpstreamListeners::new(
        registry,
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    )
}

fn watched(uri: &str) -> Interest {
    Interest::ResourceUpdated(uri.to_owned())
}

/// (a) The charge persists across retries: A's first subscribe ends in an
/// HTTP 500, a retry is answered success, and A is unwatched. The peer may
/// still hold the first one, so A keeps a key: with A and `MAX_URIS - 1`
/// other URIs counted, one more distinct URI is refused.
#[tokio::test]
async fn an_uncertain_subscribe_stays_charged_across_retries_after_unwatch() {
    let (peer, url) = Peer::start().await;
    let listeners = listeners_for(&url);
    listeners.add("b", &watched(URI_A)).expect("room for A");
    peer.until("the first subscribe of A", |p| p.subscribes_of(URI_A) >= 1)
        .await;
    // A second URI wakes a pass, which retries A.
    listeners.add("b", &watched("u:0")).expect("room for u:0");
    peer.until("a retried subscribe of A", |p| p.subscribes_of(URI_A) >= 2)
        .await;
    listeners.remove("b", &watched(URI_A));
    for i in 1..MAX_URIS - 1 {
        listeners
            .add("b", &watched(&format!("u:{i}")))
            .expect("room below the cap");
    }
    assert!(
        listeners.add("b", &watched("u:last")).is_err(),
        "A's uncertain subscribe still counts against the URI cap after its watcher left"
    );
}
