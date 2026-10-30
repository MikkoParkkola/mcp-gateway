// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A lent-only per-user slot's era re-probe goes out as the subscriber whose
//! answer contradicted the era, while that subscriber's dispatch still lends
//! its credential. A re-probe detached past the dispatch has no loan, so the
//! slot sends nothing and its era stays unresolved.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::{Value, json};

use super::Backend;
use super::slot_eviction_tests::{AUDIENCE, slot, subscriber_credential};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::era::PeerEra;

const USER: &str = "u:alpha";

/// A peer that answers its first `server/discover` as a 2026 server and every
/// later one `method not found`, recording each request's method and
/// `Authorization` header.
async fn peer_that_turns_legacy() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let discovers = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new().fallback({
        let seen = Arc::clone(&seen);
        move |headers: HeaderMap, axum::Json(message): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            let discovers = Arc::clone(&discovers);
            async move {
                let method = message["method"].as_str().unwrap_or_default().to_string();
                let auth = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                seen.lock().unwrap().push((method.clone(), auth));
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let body = match method.as_str() {
                    "server/discover" if discovers.fetch_add(1, Ordering::SeqCst) == 0 => {
                        json!({ "jsonrpc": "2.0", "id": id, "result": {
                            "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                            "capabilities": {}
                        }})
                    }
                    "initialize" => json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": { "name": "turns-legacy", "version": "0" }
                    }}),
                    _ => json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": "method not found" } }),
                };
                axum::Json(body)
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

/// An HTTP backend at `url` whose identity binding is required, so each
/// per-user slot is lent-only.
fn required_backend_at(url: String) -> Arc<Backend> {
    Arc::new(Backend::new(
        "era-lent-reprobe",
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
                required: true,
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

/// The subscriber's own `server/discover` comes back `method not found` from
/// a slot resolved modern. The re-probe that answer starts reaches the peer
/// as that subscriber before the dispatch returns, and the slot's era is
/// decided by it.
#[tokio::test(flavor = "current_thread")]
async fn a_lent_only_slots_reprobe_goes_out_as_the_subscriber() {
    let (url, seen) = peer_that_turns_legacy().await;
    let backend = required_backend_at(url);
    let credential = subscriber_credential(USER);
    let bearer = credential[0].1.clone();

    let _ = backend
        .request_with_headers("server/discover", None, &credential, Some(USER))
        .await;

    let discovers: Vec<(String, String)> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, _)| method == "server/discover")
        .cloned()
        .collect();
    assert!(
        discovers.len() >= 2,
        "premise: the slot's start probe and the subscriber's own discover reached the peer: {discovers:?}"
    );
    assert!(
        discovers.iter().all(|(_, auth)| *auth == bearer),
        "a discover reached the peer other than as the subscriber: {discovers:?}"
    );
    assert_eq!(
        discovers.len(),
        3,
        "the re-probe did not reach the peer while the dispatch lent its credential: {discovers:?}"
    );
    let era = backend
        .pool
        .get(&slot(USER))
        .expect("the slot")
        .value()
        .era
        .cached_now();
    assert_eq!(era, Some(PeerEra::Legacy), "the re-probe decided the era");
}
