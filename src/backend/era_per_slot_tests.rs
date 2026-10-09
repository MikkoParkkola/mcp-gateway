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
    upstream(false).await
}

/// An MCP server on loopback that records what it receives; `answers_modern` makes it
/// answer `server/discover` with a 2026 discovery document.
async fn upstream(answers_modern: bool) -> (String, Arc<Mutex<Vec<Seen>>>) {
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
                    "server/discover" if answers_modern => {
                        json!({ "jsonrpc": "2.0", "id": id, "result": {
                            "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                            "capabilities": {}
                        }})
                    }
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

/// PERSLOT.3a, the other start order: the per-user slot resolves first, the
/// Shared slot after. Each slot keeps its own peer's verdict.
#[tokio::test]
async fn each_slot_keeps_its_own_verdict_whichever_starts_first() {
    let (url, _seen) = legacy_upstream().await;
    let backend = backend_at(url);
    per_user_slot_resolved(&backend, Answer::Modern).await;
    backend
        .ensure_started()
        .await
        .expect("the Shared slot starts");

    let per_user = Arc::clone(backend.pool.get(&slot(USER)).expect("the slot").value());
    assert_eq!(per_user.era.cached().await, Some(Era::Modern));
    assert_eq!(backend.cached_era().await, Some(Era::Legacy));
}

/// PERSLOT.3a: a contradiction-driven re-probe on one slot drops and
/// re-resolves only that slot's verdict.
#[tokio::test]
async fn a_reprobe_on_one_slot_leaves_the_other_slots_verdict() {
    let (url, _seen) = legacy_upstream().await;
    let backend = backend_at(url);
    backend
        .ensure_started()
        .await
        .expect("the Shared slot starts");
    let (peer, _handles) = Peer::new(Answer::Modern);
    let peer: Arc<dyn Transport> = peer;
    backend.set_pooled_transport_for_test(&slot(USER), Arc::clone(&peer));
    let per_user = Arc::clone(backend.pool.get(&slot(USER)).expect("the slot").value());
    backend.resolve_era_for_entry_test(&peer, &per_user).await;

    backend
        .reprobe_if_code_contradicts(
            "server/discover",
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            &peer,
        )
        .await;
    // The re-probe holds the slot's era lock while it runs: this read waits for it.
    let _ = tokio::time::timeout(Duration::from_secs(20), per_user.era.cached()).await;

    assert_eq!(backend.cached_era().await, Some(Era::Legacy));
}

/// PERSLOT.3c: a removed method is judged by the era of the slot the request
/// is dispatched to: forwarded to a legacy per-user peer, refused before the
/// wire for the modern Shared peer beside it.
#[tokio::test]
async fn a_removed_method_is_judged_by_its_own_slots_era() {
    let backend = backend_at("http://127.0.0.1:9/mcp".to_string());
    let (shared, _h1) = Peer::new(Answer::Modern);
    let shared: Arc<dyn Transport> = shared;
    backend.set_pooled_transport_for_test(&super::pool::PoolKey::Shared, Arc::clone(&shared));
    backend
        .resolve_era_for_entry_test(&shared, &backend.shared_entry())
        .await;
    per_user_slot_resolved(&backend, Answer::MethodNotFound).await;

    let per_user = backend
        .request_with_headers("ping", None, &[], Some(USER))
        .await;
    assert!(
        per_user.is_ok(),
        "a legacy per-user peer is sent ping: {per_user:?}"
    );
    let shared_refused = backend
        .request("ping", None)
        .await
        .expect_err("the modern Shared peer is not sent ping");
    assert!(
        super::removed_method_refusal_message(&shared_refused).is_some(),
        "{shared_refused:?}"
    );
}

/// PERSLOT.3c, cold slot: a new caller's first removed-method request is
/// judged after its slot's own start has probed, so a modern peer is never
/// sent it, even on the first call.
#[tokio::test]
async fn a_cold_slots_first_removed_method_is_judged_after_its_probe() {
    let (url, seen) = upstream(true).await;
    let backend = backend_at(url);
    assert!(
        backend.shared_entry().transport.read().is_none(),
        "premise: cold"
    );

    let refused = backend
        .request("ping", None)
        .await
        .expect_err("a modern peer is not sent ping");
    assert!(
        super::removed_method_refusal_message(&refused).is_some(),
        "{refused:?}"
    );
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|s| s.method == "server/discover"),
        "premise: the start probed: {seen:?}"
    );
    assert!(
        !seen.iter().any(|s| s.method == "ping"),
        "ping reached a modern peer: {seen:?}"
    );
}

/// PERSLOT.3c, admission first: a slot whose breaker refuses the request is
/// not started to judge a removed method; nothing reaches the server.
#[tokio::test]
async fn a_refused_admission_starts_no_slot_for_a_removed_method() {
    let (url, seen) = upstream(true).await;
    let backend = backend_at(url);
    backend.trip_circuit_breaker_for_test();

    let refused = backend
        .request("ping", None)
        .await
        .expect_err("the open breaker refuses");
    assert!(
        super::removed_method_refusal_message(&refused).is_none(),
        "refused by admission, not judged: {refused:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "a refused request started the slot: {:?}",
        seen.lock().unwrap()
    );
}

/// PERSLOT.3a, attachment: a per-user HTTP slot's frames are shaped by its own
/// slot's verdict. The Shared slot is never started, so a transport attached
/// the Shared cache would read no verdict and send legacy frames.
#[tokio::test]
async fn a_per_user_transport_is_shaped_by_its_own_slots_verdict() {
    let (url, seen) = upstream(true).await;
    let backend = backend_at(url);

    let _ = backend
        .request_with_headers("tools/list", None, &[], Some(USER))
        .await;

    assert!(
        backend.shared_entry().transport.read().is_none(),
        "premise: the Shared slot stayed cold"
    );
    let seen = seen.lock().unwrap().clone();
    let list: Vec<_> = seen.iter().filter(|s| s.method == "tools/list").collect();
    assert!(
        !list.is_empty(),
        "premise: tools/list reached the server: {seen:?}"
    );
    assert!(
        list.iter().all(|s| s.modern),
        "the per-user slot's modern peer was sent a legacy frame: {seen:?}"
    );
}

/// PERSLOT.3a, re-probe target: with the Shared slot not yet probed, a
/// per-user slot's re-probe re-resolves that slot only; the Shared view stays
/// unresolved.
#[tokio::test]
async fn a_per_user_reprobe_does_not_resolve_a_cold_shared_slot() {
    let backend = backend_at("http://127.0.0.1:9/mcp".to_string());
    let (peer, _handles) = Peer::new(Answer::Modern);
    let peer: Arc<dyn Transport> = peer;
    backend.set_pooled_transport_for_test(&slot(USER), Arc::clone(&peer));
    let per_user = Arc::clone(backend.pool.get(&slot(USER)).expect("the slot").value());
    backend.resolve_era_for_entry_test(&peer, &per_user).await;

    backend
        .reprobe_if_code_contradicts(
            "server/discover",
            crate::protocol::era::METHOD_NOT_FOUND_CODE,
            &peer,
        )
        .await;
    let _ = tokio::time::timeout(Duration::from_secs(20), per_user.era.cached()).await;

    assert_eq!(
        per_user.era.cached().await,
        Some(Era::Modern),
        "re-resolved"
    );
    assert_eq!(backend.cached_era().await, None);
}
