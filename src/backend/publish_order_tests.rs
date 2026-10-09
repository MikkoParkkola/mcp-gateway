// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table T04 (MIK-7897 LIFE.3a, design r3 L3, finding #11): a
//! published transport is never visible without its listen handle, so an
//! events listener that reads the slot between the two cannot see "no event
//! stream" for a backend that has one.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use super::{Backend, MarkWindowGate};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// An MCP server on loopback that answers the handshake, so a start runs all
/// the way to publish.
async fn upstream() -> String {
    let app = axum::Router::new().fallback(|axum::Json(message): axum::Json<Value>| async move {
        let Some(id) = message.get("id").cloned() else {
            return StatusCode::ACCEPTED.into_response();
        };
        let body = match message["method"].as_str() {
            Some("initialize") => json!({ "jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": { "name": "order", "version": "0" }
            }}),
            _ => json!({ "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": "method not found" } }),
        };
        axum::Json(body).into_response()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    url
}

#[tokio::test]
async fn t04_a_published_transport_carries_its_listen_handle() {
    let backend = Arc::new(Backend::new(
        "order",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: upstream().await,
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
    *backend.publish_gate.lock() = Some(Arc::clone(&gate));
    let start = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.ensure_started().await }
    });
    tokio::time::timeout(Duration::from_secs(30), gate.reached.notified())
        .await
        .expect("the start reached publish");
    let entry = backend.shared_entry();
    let published = entry.transport.read().is_some();
    let listening = entry.listen.read().is_some();
    gate.release.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(30), start).await;
    assert!(published, "premise: the transport is published");
    assert!(listening, "its listen handle is published with it");
}
