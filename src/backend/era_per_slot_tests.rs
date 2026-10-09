// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8186 PERSLOT: one slot's era verdict never shapes another slot's
//! frames, nor the backend-level view the Shared slot reports.
//!
//! Every slot of a backend reaches its own peer. While a rolling upgrade has
//! the Shared slot on an older server and a user's per-user slot on a newer
//! one, a verdict about one peer must not decide the dialect spoken to the
//! other.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use super::Backend;
use super::era_stale_probe_tests::{Answer, Peer};
use super::slot_eviction_tests::{AUDIENCE, slot};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::era::Era;
use crate::transport::Transport;

const USER: &str = "u:alpha";

/// One request the loopback server received: its method, and whether it was
/// shaped for the 2026 revision (a `_meta` object in its params).
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    modern: bool,
}

/// A legacy MCP server on loopback: `server/discover` is unknown to it.
async fn legacy_upstream() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = axum::Router::new().fallback({
        let seen = Arc::clone(&seen);
        move |axum::Json(message): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let method = message["method"].as_str().unwrap_or_default().to_string();
                let modern = message["params"].get("_meta").is_some();
                seen.lock().unwrap().push(Seen {
                    method: method.clone(),
                    modern,
                });
                let Some(id) = message.get("id").cloned() else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let body = match method.as_str() {
                    "initialize" => json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": { "name": "legacy", "version": "0" }
                    }}),
                    "tools/list" => {
                        json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [] } })
                    }
                    _ => json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": "method not found" } }),
                };
                axum::Json(body).into_response()
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, seen)
}

/// An HTTP backend at `url` that also keeps one slot per caller identity.
fn backend_at(url: String) -> Arc<Backend> {
    Arc::new(Backend::new(
        "era-per-slot",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: AUDIENCE.to_string(),
                required: false,
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

/// A per-user slot whose peer answered `answer`, its era resolved on that
/// slot's own start path.
async fn per_user_slot_resolved(backend: &Arc<Backend>, answer: Answer) {
    let (peer, _handles) = Peer::new(answer);
    let peer: Arc<dyn Transport> = peer;
    backend.set_pooled_transport_for_test(&slot(USER), Arc::clone(&peer));
    let entry = Arc::clone(backend.pool.get(&slot(USER)).expect("the slot").value());
    backend.resolve_era_for_entry_test(&peer, &entry).await;
}

/// PERSLOT.3a: the Shared slot reaches a legacy server. A per-user slot's
/// probe finds a modern peer. A request through the Shared slot is still
/// shaped legacy: the frame on the wire carries no `_meta`.
#[tokio::test]
async fn another_slots_modern_verdict_does_not_shape_the_shared_slots_frames() {
    let (url, seen) = legacy_upstream().await;
    let backend = backend_at(url);
    backend
        .ensure_started()
        .await
        .expect("the Shared slot starts");
    per_user_slot_resolved(&backend, Answer::Modern).await;

    let _ = backend.request("tools/list", None).await;

    let seen = seen.lock().unwrap().clone();
    let list: Vec<_> = seen.iter().filter(|s| s.method == "tools/list").collect();
    assert!(
        !list.is_empty(),
        "premise: tools/list reached the server: {seen:?}"
    );
    assert!(
        list.iter().all(|s| !s.modern),
        "a legacy peer was sent a 2026-shaped frame because another slot's peer is modern: {seen:?}"
    );
}

/// PERSLOT.3b: the backend-level view (liveness, `gateway_list_servers`)
/// follows the Shared slot, not the slot that probed last.
#[tokio::test]
async fn the_backend_view_follows_the_shared_slot_not_the_last_prober() {
    let (url, _seen) = legacy_upstream().await;
    let backend = backend_at(url);
    backend
        .ensure_started()
        .await
        .expect("the Shared slot starts");
    assert_eq!(backend.cached_era().await, Some(Era::Legacy), "premise");

    per_user_slot_resolved(&backend, Answer::Modern).await;

    assert_eq!(backend.cached_era().await, Some(Era::Legacy));
    assert_eq!(backend.liveness_method().await, "ping");
}

/// PERSLOT.3b, the other direction: a per-user slot's legacy verdict does
/// not demote a Shared slot whose peer is modern.
#[tokio::test]
async fn a_per_user_legacy_verdict_does_not_demote_the_shared_slot() {
    let backend = backend_at("http://127.0.0.1:9/mcp".to_string());
    let (shared, _handles) = Peer::new(Answer::Modern);
    let shared: Arc<dyn Transport> = shared;
    backend.set_pooled_transport_for_test(&super::pool::PoolKey::Shared, Arc::clone(&shared));
    let entry = backend.shared_entry();
    backend.resolve_era_for_entry_test(&shared, &entry).await;
    assert_eq!(backend.cached_era().await, Some(Era::Modern), "premise");

    per_user_slot_resolved(&backend, Answer::MethodNotFound).await;

    assert_eq!(backend.cached_era().await, Some(Era::Modern));
}
