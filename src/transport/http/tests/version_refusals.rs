// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8195 W1: the legacy handshake's protocol-version refusals, each against
//! a loopback peer. A backend that shares no version with this gateway, by
//! HTTP status or by JSON-RPC error, is refused; a retry with a negotiated
//! version that the backend still rejects is refused; a shared version is
//! negotiated and connects.

use std::sync::atomic::AtomicUsize;

use serde_json::json;

use super::*;

/// A version this gateway never speaks.
const FOREIGN: &str = "1999-01-01";

/// One scripted answer to the nth POST: a status and a JSON body.
type Script = Arc<dyn Fn(usize, &Value) -> (u16, Value) + Send + Sync>;

/// A Streamable peer whose nth POST (from 0) is answered by `script`.
async fn peer(script: Script) -> (String, tokio::task::JoinHandle<()>) {
    use axum::{
        Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post,
    };

    async fn on_post(
        State((script, calls)): State<(Script, Arc<AtomicUsize>)>,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }
        let n = calls.fetch_add(1, Ordering::Relaxed);
        let (status, answer) = script(n, &body);
        (StatusCode::from_u16(status).unwrap(), Json(answer)).into_response()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(on_post))
        .with_state((script, Arc::new(AtomicUsize::new(0))));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), server)
}

fn version_error(id: &Value, supported: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32602, "message": format!("Unsupported protocol version. Supported versions: {supported}")}
    })
}

fn initialized(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "mock", "version": "0"}
        }
    })
}

/// Initialize a Streamable transport against `script`; the result and whether
/// the transport ended connected.
async fn initialize(script: Script) -> (crate::Result<()>, bool) {
    let (url, server) = peer(script).await;
    let transport = make_transport(&url);
    let result = transport.initialize().await;
    let connected = transport.is_connected();
    server.abort();
    (result, connected)
}

#[tokio::test]
async fn a_status_refusal_sharing_no_version_is_refused() {
    let (result, connected) = initialize(Arc::new(|_, body| {
        (400, version_error(&body["id"], FOREIGN))
    }))
    .await;
    let err = result.expect_err("no shared version");
    assert!(err.to_string().contains("shares none"), "{err}");
    assert!(!connected, "connected without a shared version");
}

#[tokio::test]
async fn a_status_refusal_naming_a_shared_version_negotiates_it() {
    let (result, connected) = initialize(Arc::new(|n, body| match n {
        0 => (400, version_error(&body["id"], "2024-11-05")),
        _ => (200, initialized(&body["id"])),
    }))
    .await;
    result.expect("a shared version connects");
    assert!(connected, "not connected after negotiation");
}

#[tokio::test]
async fn a_jsonrpc_refusal_sharing_no_version_is_refused() {
    let (result, connected) = initialize(Arc::new(|_, body| {
        (200, version_error(&body["id"], FOREIGN))
    }))
    .await;
    let err = result.expect_err("no shared version");
    assert!(
        err.to_string()
            .contains("Protocol version negotiation failed"),
        "{err}"
    );
    assert!(!connected, "connected without a shared version");
}

#[tokio::test]
async fn a_negotiated_version_the_backend_still_rejects_is_refused() {
    let (result, connected) = initialize(Arc::new(|n, body| match n {
        0 => (200, version_error(&body["id"], "2024-11-05")),
        _ => (
            200,
            json!({"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32000, "message": "still no"}}),
        ),
    }))
    .await;
    let err = result.expect_err("the retry was refused");
    assert!(
        err.to_string()
            .contains("Initialize failed with negotiated version 2024-11-05"),
        "{err}"
    );
    assert!(!connected, "connected after a refused retry");
}
