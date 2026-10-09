// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7936: a start that `stop()` overtakes after it passed the start-time
//! check is refused at publish. That refusal is pre-dispatch like the
//! start-time one: the instance is retired, nothing was sent, and a retry
//! under the same idempotency key must reach the backend that replaced it.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse as _;
use serde_json::{Value, json};

use super::{Backend, MarkWindowGate};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// An MCP server on loopback that answers the handshake and accepts
/// notifications, so a start runs all the way to publish.
async fn upstream() -> String {
    let app = axum::Router::new().fallback(|axum::Json(message): axum::Json<Value>| async move {
        let Some(id) = message.get("id").cloned() else {
            return StatusCode::ACCEPTED.into_response();
        };
        let body = match message["method"].as_str() {
            Some("initialize") => json!({ "jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": { "name": "retired", "version": "0" }
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

/// Bounds a wait in a window test, so a regression fails instead of hanging.
pub(super) async fn within<T>(what: &str, wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), wait)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within 30s"))
}

#[tokio::test]
async fn a_start_overtaken_by_stop_refuses_as_not_found() {
    let backend = Arc::new(Backend::new(
        "retired",
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
    *backend.mark_window_gate.lock() = Some(Arc::clone(&gate));

    // Held after the start-time stop check, before it connects.
    let start = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.ensure_started().await }
    });
    within("the start reaching the window", gate.reached.notified()).await;
    let stop = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.stop().await }
    });
    within("stop latching", async {
        while !backend.replaced_transport_cleanups.lock().stopping {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    gate.release.notify_one();

    let error = within("the start returning", start)
        .await
        .expect("start task")
        .expect_err("a start that shutdown overtook is not published");
    assert!(
        matches!(error, crate::Error::BackendNotFound(_)),
        "the retired instance answers NotFound, got {error:?}"
    );
    assert!(
        error.is_pre_dispatch(),
        "refused before dispatch, so the key is freed: {error:?}"
    );
    within("stop returning", stop)
        .await
        .expect("stop task")
        .expect("stop");
}
