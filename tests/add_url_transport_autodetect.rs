// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway add --url` must produce a backend that works against both
//! HTTP server shapes the MCP spec allows, driven through the shipped binary.
//!
//! The spec's backwards-compatibility rule: POST `initialize` first (Streamable
//! HTTP) and fall back to the legacy SSE `GET` only when that POST is refused
//! with a 4xx. A streamable-only server answers `GET` with 405, so a config
//! that always opens with `GET` fails on its first call. An explicit flag
//! that the server refuses with such a 4xx gets one try of the other transport.

use stdio_session::gateway_bin;

#[path = "common/stdio_session.rs"]
mod stdio_session;

use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use stdio_session::StdioSession;

const BACKEND: &str = "fx";

/// Every `(HTTP method, path)` the fixture saw, in arrival order.
type Hits = Arc<Mutex<Vec<(Method, String)>>>;

fn answer(request: &Value, flavour: &str) -> Response {
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": flavour, "version": "0"},
        }),
        Some("tools/list") => json!({"tools": [{
            "name": "ping",
            "description": "answers pong",
            "inputSchema": {"type": "object"},
        }]}),
        Some("tools/call") => {
            json!({"content": [{"type": "text", "text": format!("pong-{flavour}")}]})
        }
        _ => {
            return axum::Json(json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}}))
            .into_response();
        }
    };
    axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

fn recording(hits: &Hits) -> impl Fn(Method, String) + Clone + Send + Sync + use<> {
    let hits = Arc::clone(hits);
    move |method, path| hits.lock().expect("hits").push((method, path))
}

/// A spec-shaped Streamable HTTP server: `POST /mcp` answers, `GET /mcp` is 405.
async fn streamable_server(hits: &Hits) -> String {
    let record = recording(hits);
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::any(move |method: Method, body: Bytes| {
            let record = record.clone();
            async move {
                record(method.clone(), "/mcp".into());
                if method != Method::POST {
                    return StatusCode::METHOD_NOT_ALLOWED.into_response();
                }
                let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                answer(&request, "streamable")
            }
        }),
    );
    format!("{}/mcp", serve(app).await)
}

/// A legacy HTTP+SSE server: `GET /sse` names the message endpoint and stays
/// open; `POST /sse` is 405; requests go to `POST /messages`.
async fn sse_server(hits: &Hits) -> String {
    let record = recording(hits);
    let record_messages = record.clone();
    let app = axum::Router::new()
        .route(
            "/sse",
            axum::routing::any(move |method: Method| {
                let record = record.clone();
                async move {
                    record(method.clone(), "/sse".into());
                    if method != Method::GET {
                        return StatusCode::METHOD_NOT_ALLOWED.into_response();
                    }
                    let first = futures::stream::once(async {
                        Ok::<_, Infallible>(Bytes::from("event: endpoint\ndata: /messages\n\n"))
                    });
                    let body = Body::from_stream(futures::StreamExt::chain(
                        first,
                        futures::stream::pending(),
                    ));
                    ([("content-type", "text/event-stream")], body).into_response()
                }
            }),
        )
        .route(
            "/messages",
            axum::routing::post(move |body: Bytes| {
                let record = record_messages.clone();
                async move {
                    record(Method::POST, "/messages".into());
                    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    answer(&request, "sse")
                }
            }),
        );
    format!("{}/sse", serve(app).await)
}

fn add(home: &Path, url: &str) {
    let output = gateway_bin::command(home, gateway_bin::Inherit::Environment)
        .args(["add", "--url", url, BACKEND, "--config"])
        .arg(home.join("gateway.yaml"))
        .output()
        .expect("run mcp-gateway add");
    assert!(
        output.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Drive one `gateway_invoke` of the fixture's `ping` through `serve --stdio`.
async fn invoke_ping(home: &Path) -> Value {
    let mut session = StdioSession::spawn(home);
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "add-url-autodetect", "version": "0"},
            }}),
        )
        .await;
    let (_, init) = session.read_until_id(1).await;
    assert!(init.is_some(), "the gateway never answered initialize");
    session
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    session
        .send(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": "ping", "arguments": {}},
            }}),
        )
        .await;
    let (lines, reply) = session.read_until_id(2).await;
    session.shutdown().await;
    reply.unwrap_or_else(|| panic!("no reply to the invoke; saw: {lines:?}"))
}

#[tokio::test]
async fn add_url_reaches_a_streamable_only_server() {
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    add(home.path(), &url);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-streamable"),
        "a streamable-only server must work after `add --url`; reply: {reply}"
    );
}

#[tokio::test]
async fn add_url_still_reaches_a_legacy_sse_server() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    add(home.path(), &url);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-sse"),
        "a legacy SSE server must still work after `add --url`; reply: {reply}"
    );
}

#[tokio::test]
async fn add_url_leaves_the_transport_to_detection() {
    let home = tempfile::tempdir().expect("home");
    add(home.path(), "https://mcp.example.test/mcp");
    let yaml = std::fs::read_to_string(home.path().join("gateway.yaml")).expect("gateway.yaml");
    assert!(
        !yaml.contains("streamable_http"),
        "`add --url` must not pin a transport the server was never asked about:\n{yaml}"
    );
}

fn write_explicit(home: &Path, url: &str, streamable: bool) {
    let yaml = format!(
        "backends:\n  {BACKEND}:\n    http_url: \"{url}\"\n    streamable_http: {streamable}\n"
    );
    mcp_gateway::gateway::test_helpers::write_owner_only(home.join("gateway.yaml"), yaml)
        .expect("write gateway.yaml");
}

/// An explicit `streamable_http: false` that the server accepts is used as
/// written: the gateway opens with the SSE `GET` and never probes with a `POST`.
#[tokio::test]
async fn explicit_streamable_false_is_honoured() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, false);

    let reply = invoke_ping(home.path()).await;
    assert!(reply.to_string().contains("pong-sse"), "reply: {reply}");
    let posts_to_sse = hits
        .lock()
        .expect("hits")
        .iter()
        .filter(|(method, path)| *method == Method::POST && path == "/sse")
        .count();
    assert_eq!(posts_to_sse, 0, "explicit `false` must not probe with POST");
}

/// The config the old `add --url` wrote: an explicit `false` naming a server
/// that speaks only Streamable HTTP. The refused `GET` costs one request, not
/// the backend.
#[tokio::test]
async fn an_old_add_config_reaches_a_streamable_only_server() {
    let hits = Hits::default();
    let url = streamable_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, false);

    let reply = invoke_ping(home.path()).await;
    assert!(
        reply.to_string().contains("pong-streamable"),
        "reply: {reply}"
    );
}

/// The mirror case: an explicit `true` naming a legacy SSE server.
#[tokio::test]
async fn explicit_streamable_true_still_reaches_a_legacy_sse_server() {
    let hits = Hits::default();
    let url = sse_server(&hits).await;
    let home = tempfile::tempdir().expect("home");
    write_explicit(home.path(), &url, true);

    let reply = invoke_ping(home.path()).await;
    assert!(reply.to_string().contains("pong-sse"), "reply: {reply}");
}
