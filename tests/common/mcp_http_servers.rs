// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Local MCP servers in each HTTP shape the spec allows, recording every
//! request: a Streamable HTTP server (`POST /mcp` answers, `GET` is 405) and a
//! legacy HTTP+SSE server (`GET /sse` names the message endpoint).

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

/// Every `(HTTP method, path)` the fixture saw, in arrival order.
pub type Hits = Arc<Mutex<Vec<(Method, String)>>>;

pub fn answer(request: &Value, flavour: &str) -> Response {
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

pub async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

pub fn recording(hits: &Hits) -> impl Fn(Method, String) + Clone + Send + Sync + use<> {
    let hits = Arc::clone(hits);
    move |method, path| hits.lock().expect("hits").push((method, path))
}

/// A spec-shaped Streamable HTTP server: `POST /mcp` answers, `GET /mcp` is 405.
pub async fn streamable_server(hits: &Hits) -> String {
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
pub async fn sse_server(hits: &Hits) -> String {
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
