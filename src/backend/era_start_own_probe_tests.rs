// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8056 ERAPROOF.2: an HTTP start's handshake follows the era its own
//! probe decided, never a verdict another writer put in the backend-wide
//! cache between that probe and the handshake decision.
//!
//! The start is held at the era-decision gate, after `resolve_era` returned
//! and before the handshake shape is chosen. While held, another writer
//! (a concurrent start of another slot) installs the opposite verdict.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use super::era_stale_probe_tests::{Answer, Peer};
use super::stop_race_tests::within;
use super::{Backend, MarkWindowGate};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::protocol::era::{Era, EraCache, METHOD_NOT_FOUND_CODE, ProbeOutcome};
use crate::transport::Transport;

/// What the loopback server answers `server/discover` with.
#[derive(Clone, Copy)]
enum Discover {
    /// HTTP 500: the probe reads silence, so this start's own era is Legacy.
    Fails,
    /// A modern discover result: this start's own era is Modern.
    Modern,
}

/// An MCP server on loopback that records every method it receives.
async fn upstream(discover: Discover) -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = axum::Router::new().fallback({
        let seen = Arc::clone(&seen);
        move |axum::Json(message): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            async move {
                let method = message["method"].as_str().unwrap_or_default().to_string();
                seen.lock().unwrap().push(method.clone());
                let Some(id) = message.get("id").cloned() else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let result = match (method.as_str(), discover) {
                    ("server/discover", Discover::Fails) => {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    ("server/discover", Discover::Modern) => json!({
                        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                        "capabilities": {},
                    }),
                    ("initialize", _) => json!({
                        "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                        "capabilities": {},
                        "serverInfo": { "name": "era-own", "version": "0" }
                    }),
                    _ => json!({}),
                };
                axum::Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
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

/// Start an HTTP backend against `discover`, hold it at the era decision,
/// let `other` install its verdict, then finish the start. Returns the
/// methods the server received.
async fn start_while_another_writer_installs(
    discover: Discover,
    other: Answer,
    other_era: Era,
) -> Vec<String> {
    let (url, seen) = upstream(discover).await;
    let backend = Arc::new(Backend::new(
        "era-own",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let gate = Arc::new(MarkWindowGate::default());
    *backend.era_decision_gate.lock() = Some(Arc::clone(&gate));

    let start = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.ensure_started().await }
    });
    within(
        "the start reaching the era decision",
        gate.reached.notified(),
    )
    .await;

    // Another slot's start: an unpooled entry always serves, so it installs.
    let (peer, _handles) = Peer::new(other);
    let peer: Arc<dyn Transport> = peer;
    backend.resolve_era_for_test(&peer).await;
    assert_eq!(
        backend.cached_era().await,
        Some(other_era),
        "precondition: the other writer's verdict is in the shared cache"
    );

    gate.release.notify_one();
    within("the start finishing", start)
        .await
        .expect("start task")
        .expect("the start succeeds");
    seen.lock().unwrap().clone()
}

/// ERAPROOF.2a: this start's probe was silent (Legacy), another writer
/// installed Modern meanwhile. The start must still handshake.
#[tokio::test]
async fn a_silent_start_probe_handshakes_despite_a_modern_verdict_installed_meanwhile() {
    let seen =
        start_while_another_writer_installs(Discover::Fails, Answer::Modern, Era::Modern).await;
    assert!(
        seen.iter().any(|m| m == "initialize"),
        "the start followed another writer's Modern instead of its own silent probe: {seen:?}"
    );
}

/// ERAPROOF.2b: the opposite direction. This start's probe said Modern,
/// another writer installed Legacy meanwhile. The start must skip the
/// handshake, as its own probe decided.
#[tokio::test]
async fn a_modern_start_probe_skips_the_handshake_despite_a_legacy_verdict_installed_meanwhile() {
    let seen =
        start_while_another_writer_installs(Discover::Modern, Answer::MethodNotFound, Era::Legacy)
            .await;
    assert!(
        !seen.iter().any(|m| m == "initialize"),
        "the start followed another writer's Legacy instead of its own Modern probe: {seen:?}"
    );
}

/// A discovery document naming a modern revision.
fn modern_document() -> ProbeOutcome {
    ProbeOutcome::Result(json!({
        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
        "capabilities": {},
    }))
}

/// A probe a refused start must never run.
async fn no_probe() -> ProbeOutcome {
    unreachable!("no probe runs for a retired slot")
}

/// ERAPROOF.3a: a start whose slot was retired before any probe reports
/// `Legacy`, not the verdict the shared cache holds about another peer, and
/// leaves that verdict in place.
#[tokio::test]
async fn a_start_retired_before_its_probe_reports_legacy() {
    let cache = EraCache::for_backend("retired-before-probe");
    cache.restart_with(|| async { modern_document() }).await;
    assert_eq!(cache.cached().await, Some(Era::Modern), "primed");

    let era = cache.restart_while_serving(no_probe, |_step| false).await;
    assert_eq!(era, Era::Legacy);
    assert_eq!(cache.cached().await, Some(Era::Modern));
}

/// ERAPROOF.3b: a start whose probe ran but whose slot was retired before the
/// install reports what its own probe decided, and installs nothing.
#[tokio::test]
async fn a_start_refused_at_install_reports_its_own_probe() {
    let cache = EraCache::for_backend("retired-mid-probe");
    cache
        .restart_with(|| async { ProbeOutcome::Error(METHOD_NOT_FOUND_CODE) })
        .await;
    assert_eq!(cache.cached().await, Some(Era::Legacy), "primed");

    // Serving at the discard, retired by the install.
    let calls = std::cell::Cell::new(0);
    let era = cache
        .restart_while_serving(
            || async { modern_document() },
            |step| {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    step();
                    true
                } else {
                    false
                }
            },
        )
        .await;
    assert_eq!(era, Era::Modern);
    assert_eq!(cache.cached().await, None, "discarded, nothing installed");
}
