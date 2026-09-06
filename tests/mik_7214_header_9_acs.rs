// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7214.HEADER.9a / .9b — era-conditional outbound headers and `_meta`.
//!
//! Design: `docs/design/2026-09-03-header-9-era-conditional-outbound.md`.
//! Plan: the same name with `-test-plan`.
//!
//! Every assertion here reads the **captured wire request**, never
//! `build_mcp_headers`' return value. The builder is private, it merges the
//! backend's static headers inside itself, and the `Request` path merges
//! per-request `extra_headers` *after* it returns — so a case asserting on the
//! return value sees neither the operator-override question nor the body half,
//! which is where half of HEADER.9a lives.
//!
//! The era is resolved by the **production probe** rather than primed as a
//! fixture input. That is deliberate and it is this file's load-bearing choice:
//! the plan names "every other case primes the era cache, so all of them pass
//! against a lifecycle that never attaches it" as its heaviest risk. A peer
//! that answers `server/discover` with a modern discovery document is the only
//! input these cases give the era machinery; if the lifecycle never hands the
//! cache to the transport, they fail for that reason and no other.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::protocol::PROTOCOL_VERSION;
use mcp_gateway::protocol::meta::{
    KEY_CLIENT_CAPABILITIES, KEY_CLIENT_INFO, KEY_PROTOCOL_VERSION, MODERN_VERSIONS,
};
use serde_json::{Value, json};

/// One request as it arrived on the wire: what a captured assertion reads.
#[derive(Clone)]
struct Wire {
    method: String,
    headers: HeaderMap,
    body: Value,
}

type Recorder = Arc<Mutex<Vec<Wire>>>;

/// Whether the fixture peer answers `server/discover` as a modern peer.
///
/// Named rather than a bare `bool` at the call site: `spawn_peer(true)` does
/// not say which era it means.
#[derive(Clone, Copy)]
enum Peer {
    /// Answers discovery with a document naming a modern revision.
    Modern,
    /// Answers discovery `method not found`, the way a 2025 server does.
    Legacy,
}

/// Answer one request the way the chosen peer would.
fn answer(peer: Peer, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "server/discover" {
        return match peer {
            // `classify` requires positive evidence: a discovery document whose
            // `capabilities` is an object and whose `supportedVersions` names a
            // revision in `MODERN_VERSIONS` (`src/protocol/era.rs`).
            Peer::Modern => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "capabilities": {},
                    "supportedVersions": MODERN_VERSIONS,
                }
            }),
            // Silence and every error but the modern-only codes read as legacy.
            Peer::Legacy => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "method not found" }
            }),
        };
    }
    if method == "initialize" {
        return json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": { "name": "fixture", "version": "0" }
            }
        });
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [] } })
}

/// A peer that records every request whole — headers included.
///
/// Bodies alone would answer HEADER.9a's `_meta` half and nothing about the
/// header half, and the two are emitted from different sites.
async fn spawn_peer(peer: Peer) -> (String, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorder);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().expect("recorder poisoned").push(Wire {
                        method: request
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        headers,
                        body: request.clone(),
                    });
                    axum::Json(answer(peer, &request))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture peer must get a port");
    let url = format!("http://{}/", listener.local_addr().expect("bound address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, recorder)
}

/// A backend built the way production builds one, pointed at the fixture peer.
///
/// `Backend::new` is the real constructor and it mints the era cache itself
/// (`src/backend/lifecycle.rs`), so nothing here can hand the transport an era
/// the lifecycle would not have given it.
fn backend_at(url: &str) -> Backend {
    Backend::new(
        "header9-fixture",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// The ordinary request whose shape every case reads, and what it recorded.
///
/// `server/discover` and `initialize` are filtered out: the probe and the
/// handshake are not the request under test, and `initialize` is required to
/// stay legacy-shaped whatever the era.
async fn ordinary_request(peer: Peer) -> Wire {
    let (url, recorder) = spawn_peer(peer).await;
    let backend = backend_at(&url);
    backend
        .request("tools/list", None)
        .await
        .expect("the fixture peer answers every method");
    let seen = recorder.lock().expect("recorder poisoned").clone();
    seen.into_iter()
        .find(|wire| wire.method == "tools/list")
        .expect("the ordinary request must reach the peer")
}

/// Read one header as a string, or say which one was missing.
fn header(wire: &Wire, name: &str) -> String {
    wire.headers
        .get(name)
        .unwrap_or_else(|| panic!("{name} is absent; the peer received {:?}", wire.headers))
        .to_str()
        .expect("a header this design emits is ASCII")
        .to_string()
}

/// MIK-7214.HEADER.9b — the version comes from the negotiated envelope.
///
/// The reachability case, and the only one whose failure means "the feature is
/// unreachable in production" rather than "a value is wrong". Nothing primes
/// the era: the peer answered discovery modernly and the lifecycle must carry
/// that verdict as far as the header builder on its own.
#[tokio::test]
async fn a_modern_peer_gets_the_modern_protocol_version() {
    let wire = ordinary_request(Peer::Modern).await;
    assert_eq!(
        header(&wire, "MCP-Protocol-Version"),
        MODERN_VERSIONS[0],
        "a peer that answered discovery modernly must be sent the modern \
         revision, not the legacy handshake constant"
    );
}

/// MIK-7214.HEADER.9a, body half — modern requests carry the required `_meta`.
///
/// Asserts the two keys the revision makes required and the absence of the one
/// this design declined to send. `clientInfo` is optional and self-asserted, so
/// emitting it would be an identity claim this change does not get to make;
/// asserting its absence is what stops it arriving later by accident.
#[tokio::test]
async fn a_modern_request_carries_the_required_meta() {
    let wire = ordinary_request(Peer::Modern).await;
    let meta = wire
        .body
        .get("params")
        .and_then(|params| params.get("_meta"))
        .unwrap_or_else(|| panic!("no `params._meta` in {}", wire.body));
    assert_eq!(
        meta.get(KEY_PROTOCOL_VERSION).and_then(Value::as_str),
        Some(MODERN_VERSIONS[0]),
        "the required protocol-version key must name the revision being spoken"
    );
    assert_eq!(
        meta.get(KEY_CLIENT_CAPABILITIES),
        Some(&json!({})),
        "the required client-capabilities key must be present and an object, \
         matching what the legacy handshake already declares"
    );
    assert!(
        meta.get(KEY_CLIENT_INFO).is_none(),
        "clientInfo is optional and self-asserted; this design declined it"
    );
}

/// MIK-7214.HEADER.9a — a legacy peer's requests are unchanged, asserted
/// positively.
///
/// "Unchanged behaviour" is the row most easily satisfied by a fixture that
/// never reached the code: a case asserting only "no modern header" passes
/// against a transport that never built headers at all. So this asserts what a
/// legacy request *does* carry — the handshake version — as well as what it
/// does not.
#[tokio::test]
async fn a_legacy_peer_still_gets_the_handshake_version_and_no_meta() {
    let wire = ordinary_request(Peer::Legacy).await;
    assert_eq!(
        header(&wire, "MCP-Protocol-Version"),
        PROTOCOL_VERSION,
        "a peer that refused discovery is legacy, and legacy is byte-for-byte \
         what this transport sent before this change"
    );
    assert!(
        wire.body
            .get("params")
            .and_then(|params| params.get("_meta"))
            .is_none(),
        "a legacy peer must not be sent a 2026 envelope; it received {}",
        wire.body
    );
}

/// A modern peer that hands out a session and then expires it once.
///
/// The expiry is what re-enters `initialize()` (`src/transport/http/mod.rs`
/// session-expiry retry): the era cache is already `Modern` by then, which is
/// the only state in which the handshake's era-shaping can be observed. A
/// fixture that primed the era could not produce this ordering, because the
/// re-handshake has to follow a *resolved* probe, not a planted verdict.
async fn spawn_expiring_peer() -> (String, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&recorder);
    let expired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            move |headers: HeaderMap, axum::Json(request): axum::Json<Value>| {
                let sink = Arc::clone(&sink);
                let expired = Arc::clone(&expired);
                async move {
                    let method = request
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    sink.lock().expect("recorder poisoned").push(Wire {
                        method: method.clone(),
                        headers,
                        body: request.clone(),
                    });
                    let mut out = HeaderMap::new();
                    if method == "initialize" {
                        out.insert("Mcp-Session-Id", "s1".parse().expect("ascii"));
                    }
                    // The first ordinary request expires the session; the
                    // retry after the fresh handshake succeeds.
                    if method == "tools/list"
                        && !expired.swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        let id = request.get("id").cloned().unwrap_or(Value::Null);
                        return (
                            out,
                            axum::Json(json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": { "code": -32015, "message": "session not found" }
                            })),
                        );
                    }
                    (out, axum::Json(answer(Peer::Modern, &request)))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture peer must get a port");
    let url = format!("http://{}/", listener.local_addr().expect("bound address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, recorder)
}

/// MIK-7214.HEADER.9a — the handshake stays legacy-shaped whatever the era.
///
/// The doc comment on `ordinary_request` asserts this in prose and no case
/// tested it: `initialize` reaches the peer through `send_request`, which
/// refuses the era by construction, but its `notifications/initialized`
/// travelled through the ordinary `notify` path. On a first start that reads
/// legacy only because the probe has not landed yet — on a re-handshake it is
/// a 2026 notification sent to a peer we are still introducing ourselves to.
#[tokio::test]
async fn a_reinitialize_keeps_the_initialized_notification_legacy_shaped() {
    let (url, recorder) = spawn_expiring_peer().await;
    let backend = backend_at(&url);
    backend
        .request("tools/list", None)
        .await
        .expect("the retry after the fresh handshake succeeds");
    let seen = recorder.lock().expect("recorder poisoned").clone();

    let handshakes: Vec<&Wire> = seen
        .iter()
        .filter(|wire| wire.method == "notifications/initialized")
        .collect();
    assert!(
        handshakes.len() >= 2,
        "the session-expiry retry must have re-run the handshake; saw {:?}",
        seen.iter().map(|w| &w.method).collect::<Vec<_>>()
    );
    let modern_request = seen
        .iter()
        .any(|wire| wire.method == "tools/list" && wire.body["params"].get("_meta").is_some());
    assert!(
        modern_request,
        "the era must be resolved Modern by the retry, or this case proves nothing"
    );

    let reinit = handshakes.last().expect("checked above");
    assert_eq!(
        header(reinit, "MCP-Protocol-Version"),
        PROTOCOL_VERSION,
        "the handshake notification is part of the handshake and must stay \
         legacy-shaped, the same way `initialize` itself does"
    );
    assert!(
        reinit.body.get("params").is_none()
            || reinit.body["params"].get("_meta").is_none(),
        "a handshake notification must not carry a 2026 envelope; it sent {}",
        reinit.body
    );
}
