// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7214.HEADER.9a and MIK-7213.CACHE.4a — the negotiated revision on the
//! two paths that never received it.
//!
//! `tests/mik_7214_header_9_acs.rs` drives the POST paths, where
//! `finalise_modern_headers` overwrites the handshake version. The GET stream
//! is built by `build_mcp_headers(HeaderMode::Sse, _)` and never reaches that
//! function, so a modern peer's stream was still labelled with the version the
//! legacy handshake negotiated. That is the case this file adds; nothing here
//! duplicates a row that file already owns.
//!
//! The era is resolved by the production probe, never primed: the transport
//! opens its stream inside `initialize`, so only a **second** `start()` — the
//! reconnect — can carry an era the first one had no way to know.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::response::IntoResponse;
use mcp_gateway::backend::Backend;
use mcp_gateway::cache::{KeyContext, ResponseCache};
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::protocol::PROTOCOL_VERSION;
use mcp_gateway::protocol::meta::MODERN_VERSIONS;
use serde_json::{Value, json};

/// Headers of one GET that opened the stream.
type Streams = Arc<Mutex<Vec<HeaderMap>>>;

/// How the fixture peer answers `server/discover` — the only input the era
/// machinery is given.
#[derive(Clone, Copy)]
enum Peer {
    Modern,
    Legacy,
}

fn answer(peer: Peer, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "server/discover" {
        return match peer {
            Peer::Modern => json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "capabilities": {}, "supportedVersions": MODERN_VERSIONS }
            }),
            Peer::Legacy => json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };
    }
    if method == "initialize" {
        return json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": { "name": "fixture", "version": "0" }
            }
        });
    }
    json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [] } })
}

/// An HTTP+SSE peer: `GET /` opens the stream and names the message endpoint,
/// `POST /msg` answers JSON-RPC. Only the GET's headers are recorded — the
/// POST paths are another file's rows.
async fn spawn_sse_peer(peer: Peer) -> (String, Streams) {
    let streams: Streams = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&streams);
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(move |headers: HeaderMap| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().expect("recorder poisoned").push(headers);
                    // A complete body, not a live stream: the transport reads
                    // until the endpoint event and stops, so a finite body is
                    // the whole handshake and needs no keep-alive task.
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                        "event: endpoint\ndata: /msg\n\n",
                    )
                        .into_response()
                }
            }),
        )
        .route(
            "/msg",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| async move {
                axum::Json(answer(peer, &request))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture peer must get a port");
    let url = format!("http://{}/", listener.local_addr().expect("bound address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, streams)
}

fn sse_backend_at(url: &str) -> Backend {
    Backend::new(
        "revision-wiring-fixture",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url.to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// Open the stream twice against the same backend and return the headers of
/// the reconnect — the first open predates any probe, by construction.
async fn reconnect_stream_headers(peer: Peer) -> HeaderMap {
    let (url, streams) = spawn_sse_peer(peer).await;
    let backend = sse_backend_at(&url);
    // `start()` attaches the era cache (`lifecycle.rs:379`) but never resolves
    // it; only `ensure_started` runs the probe (`lifecycle.rs:232`). Driving
    // `start()` here left `outbound_era()` at `None`, so the branch under test
    // could not fire and the failure said "wrong header" when the truth was
    // "era never determined".
    backend
        .ensure_started()
        .await
        .expect("first stream must open");
    backend.force_restart().await.expect("reconnect must open");
    let seen = streams.lock().expect("recorder poisoned").clone();
    assert!(
        seen.len() >= 2,
        "the reconnect never opened a second stream, so every assertion below \
         would read the pre-probe open; saw {} GET(s)",
        seen.len()
    );
    seen.last().expect("checked non-empty").clone()
}

fn protocol_version(headers: &HeaderMap) -> String {
    headers
        .get("MCP-Protocol-Version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn a_modern_peers_reconnected_stream_carries_the_negotiated_revision() {
    let headers = reconnect_stream_headers(Peer::Modern).await;
    assert_eq!(
        protocol_version(&headers),
        MODERN_VERSIONS[0],
        "MIK-7214.HEADER.9b: the GET stream's version must come from the \
         negotiated envelope, not the legacy handshake"
    );
}

#[tokio::test]
async fn a_legacy_peers_reconnected_stream_keeps_the_handshake_version() {
    let headers = reconnect_stream_headers(Peer::Legacy).await;
    assert_eq!(
        protocol_version(&headers),
        PROTOCOL_VERSION,
        "MIK-7214.HEADER.9a: a peer that negotiated no modern era must see no \
         modern header"
    );
}

/// MIK-7213.CACHE.4a, at the seam: the revision is a keyed dimension, so two
/// otherwise identical calls under different revisions cannot share an entry.
#[test]
fn the_response_key_separates_two_protocol_revisions() {
    let key_of = |revision| {
        ResponseCache::response_key(
            "srv",
            "tool",
            &json!({ "a": 1 }),
            "",
            Some("subject"),
            KeyContext {
                routing_profile: "default",
                protocol_revision: revision,
                policy_epoch: 0,
            },
        )
    };
    assert_ne!(key_of(Some("2026-07-28")), key_of(Some("2026-11-01")));
    assert_ne!(key_of(Some("2026-07-28")), key_of(None));
    assert_eq!(key_of(Some("2026-07-28")), key_of(Some("2026-07-28")));
}
