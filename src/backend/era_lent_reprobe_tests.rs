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

/// How the peer answers the re-probe, its third `server/discover`.
#[derive(Clone, Copy)]
enum Reprobe {
    Answers,
    /// Never answers: the peer stalls the probe.
    Stalls,
}

/// A peer that answers its first `server/discover` as a 2026 server and every
/// later one `method not found`, recording each request's method and
/// `Authorization` header.
async fn peer_that_turns_legacy() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
    peer(Reprobe::Answers).await
}

/// [`peer_that_turns_legacy`], answering the re-probe as `reprobe` says.
async fn peer(reprobe: Reprobe) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
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
                let nth = if method == "server/discover" {
                    discovers.fetch_add(1, Ordering::SeqCst)
                } else {
                    usize::MAX
                };
                if nth == 2 && matches!(reprobe, Reprobe::Stalls) {
                    std::future::pending::<()>().await;
                }
                let body = match method.as_str() {
                    "server/discover" if nth == 0 => {
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
    required_backend_with_timeout(url, Duration::from_secs(10))
}

/// [`required_backend_at`] with request timeout `timeout`.
fn required_backend_with_timeout(url: String, timeout: Duration) -> Arc<Backend> {
    backend_with(url, timeout, true)
}

/// An HTTP backend at `url` with a per-user identity binding, `required` or
/// optional, and request timeout `timeout`.
fn backend_with(url: String, timeout: Duration, required: bool) -> Arc<Backend> {
    Arc::new(Backend::new(
        "era-lent-reprobe",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout,
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: AUDIENCE.to_string(),
                required,
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
    reprobe_carries_the_bearer(subscriber_credential(USER)).await;
}

/// The same, with a gateway-owned mirror header beside the credential on the
/// call: the mirror is not part of the credential, and the re-probe still
/// carries the bearer.
#[tokio::test(flavor = "current_thread")]
async fn a_mirror_header_on_the_call_does_not_hide_the_credential_from_the_reprobe() {
    let mut credential = subscriber_credential(USER);
    credential.push(("Mcp-Param-Region".to_string(), "eu".to_string()));
    reprobe_carries_the_bearer(credential).await;
}

async fn reprobe_carries_the_bearer(credential: Vec<(String, String)>) {
    let (url, seen) = peer_that_turns_legacy().await;
    let backend = required_backend_at(url);
    let bearer = credential[0].1.clone();

    let _ = backend
        .request_with_headers_lent(
            "server/discover",
            None,
            crate::transport::LentCredential {
                headers: credential.clone().into(),
                check: Some(std::sync::Arc::new(|| Box::pin(async { Ok(()) }))),
            },
            Some(USER),
        )
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

/// The inline re-probe holds its caller only as long as the probe's cap,
/// never the backend's own request timeout: a peer that stalls the re-probe
/// releases the subscriber's call once the cap passes. The backend timeout
/// here is 30 s and the cap 2 s, so a call back within 10 s was bounded by
/// the cap.
#[tokio::test(flavor = "current_thread")]
async fn a_stalled_reprobe_holds_the_caller_no_longer_than_the_probe_cap() {
    let (url, seen) = peer(Reprobe::Stalls).await;
    let backend = required_backend_with_timeout(url, Duration::from_secs(30));
    let started = tokio::time::Instant::now();

    let _ = crate::test_pause::within(
        "the subscriber's call",
        backend.request_with_headers_lent(
            "server/discover",
            None,
            crate::transport::LentCredential {
                headers: subscriber_credential(USER).into(),
                check: Some(std::sync::Arc::new(|| Box::pin(async { Ok(()) }))),
            },
            Some(USER),
        ),
    )
    .await;

    let discovers = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(method, _)| method == "server/discover")
        .count();
    assert_eq!(
        discovers, 3,
        "premise: the re-probe reached the stalling peer"
    );
    let held = started.elapsed();
    assert!(
        held < Duration::from_secs(10),
        "the stalled re-probe held the caller {held:?}, past the probe cap"
    );
}

/// An optional binding's slot is not lent-only, so its contradicted era is
/// re-probed detached, after the call returned: that probe carries no
/// caller's credential, as it never did.
#[tokio::test(flavor = "current_thread")]
async fn a_detached_reprobe_of_an_optional_slot_carries_no_callers_credential() {
    let (url, seen) = peer_that_turns_legacy().await;
    let backend = backend_with(url, Duration::from_secs(10), false);
    let credential = subscriber_credential(USER);

    let _ = backend
        .request_with_headers("server/discover", None, &credential, Some(USER))
        .await;
    let discovers = || -> Vec<(String, String)> {
        seen.lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| method == "server/discover")
            .cloned()
            .collect()
    };
    crate::test_pause::within("the detached re-probe", async {
        while discovers().len() < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await;

    let reprobe = discovers()[2].clone();
    assert_eq!(
        reprobe.1, "",
        "a detached re-probe carried the caller's credential: {reprobe:?}"
    );
}
