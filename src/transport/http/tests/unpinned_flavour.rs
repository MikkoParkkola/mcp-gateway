// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An unpinned flavour (`streamable_http` unset) connects to a Streamable
//! HTTP server exactly as a `streamable_http: true` pin does: same requests,
//! same detected flavour, same message URL. `init` writes no pin (MIK-8044).

use std::sync::atomic::AtomicU32;

use super::*;

/// What one server saw: (GET requests, POST requests).
type Seen = Arc<(AtomicU32, AtomicU32)>;

async fn streamable_server() -> (String, Seen, tokio::task::JoinHandle<()>) {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;

    async fn on_post(
        State(seen): State<Seen>,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        seen.1.fetch_add(1, Ordering::Relaxed);
        if body.get("id").is_none() {
            return StatusCode::ACCEPTED.into_response();
        }
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", "s1".parse().unwrap());
        let result = json!({
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": {"name": "mock", "version": "0"}
            }
        });
        (StatusCode::OK, headers, Json(result)).into_response()
    }
    async fn on_get(State(seen): State<Seen>) -> StatusCode {
        seen.0.fetch_add(1, Ordering::Relaxed);
        StatusCode::METHOD_NOT_ALLOWED
    }

    let seen: Seen = Arc::new((AtomicU32::new(0), AtomicU32::new(0)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/mcp", post(on_post).get(on_get))
        .with_state(Arc::clone(&seen));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), seen, server)
}

/// Initialize a transport with `flavour` against a fresh Streamable server and
/// report what it settled on and what the server saw.
async fn connect_with(flavour: Option<bool>) -> (Option<bool>, Option<String>, u32, u32) {
    let (url, seen, server) = streamable_server().await;
    let transport = HttpTransport::with_destination(
        &url,
        HashMap::new(),
        Duration::from_secs(30),
        flavour,
        None,
        None,
        crate::security::ssrf::DestinationPolicy::Configured,
    )
    .expect("transport builds");
    transport.initialize().await.expect("initialize succeeds");
    let settled = *transport.streamable_http.read();
    let message_url = transport.message_url.read().clone();
    server.abort();
    (
        settled,
        message_url.map(|u| u.replace(&url, "<base>")),
        seen.0.load(Ordering::Relaxed),
        seen.1.load(Ordering::Relaxed),
    )
}

#[tokio::test]
async fn an_unpinned_flavour_connects_exactly_as_a_streamable_pin() {
    let pinned = connect_with(Some(true)).await;
    let unpinned = connect_with(None).await;
    assert_eq!(unpinned, pinned, "(flavour, message url, GETs, POSTs)");
    assert_eq!(unpinned.0, Some(true), "detected as Streamable HTTP");
    assert_eq!(unpinned.2, 0, "no SSE GET was tried");
}
