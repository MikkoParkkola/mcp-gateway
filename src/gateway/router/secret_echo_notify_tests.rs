// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that echoes the secret the gateway injected into its call in a
//! notification it raises during that call: the client's stream carries the
//! marker, never the secret, on every transport. Each transport scrubs the
//! notification where it parses the backend's bytes, before publishing it,
//! so the backends here are real servers, not mocks.
//!
//! The per-backend route has no stream for a backend's notifications: it
//! discards them, so its row checks that none arrives.
use axum::body::to_bytes;
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::{FixtureDir, test_router_app_state_with_backend};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// A value no ordinary frame contains.
const SECRET: &str = "notify-echo-secret-4c81e07d93ab";

/// What a backend's progress `message` reads once the secret is redacted:
/// the backends here write `key <api_key>`.
const REDACTED_LINE: &str = "key [redacted]";

type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

/// A backend named `echoes` on `transport` whose one rule injects
/// [`SECRET`] as the `api_key` argument.
async fn router_on(transport: TransportConfig) -> (axum::Router, FixtureDir) {
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(json!({
        "name": "echo-key", "value": SECRET, "inject_key": "api_key"
    }))
    .expect("rule parses");
    let backend = Arc::new(Backend::new(
        "echoes",
        BackendConfig {
            enabled: true,
            transport,
            secrets: vec![rule],
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(30),
    ));
    let (state, store) = test_router_app_state_with_backend(backend).await;
    (create_router(state), store)
}

/// POST `body` to `uri` offering a stream; the whole body as text.
async fn post_stream(router: &axum::Router, uri: &str, body: Value) -> String {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

/// One `echo` call on the meta route, carrying the client's progress token
/// `p1`; the streamed body.
async fn meta_call(router: &axum::Router) -> String {
    post_stream(
        router,
        "/mcp",
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}},
            "_meta": {"progressToken": "p1"}
        }}),
    )
    .await
}

/// Every `notifications/progress` frame in a streamed body.
fn progress_frames(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .filter(|frame| frame["method"] == "notifications/progress")
        .collect()
}

/// The one progress frame the client's call `p1` received; its `message`.
fn the_progress_message(body: &str) -> String {
    let frames = progress_frames(body);
    let [frame] = frames.as_slice() else {
        panic!("premise: one progress frame reached the client: {body}");
    };
    assert_eq!(
        frame["params"]["progressToken"], "p1",
        "premise: the frame is the call's own progress: {body}"
    );
    frame["params"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("premise: the frame has a message: {body}"))
        .to_owned()
}

/// A Streamable HTTP MCP server on a loopback port that lists one `echo`
/// tool and answers each call as an event stream: a progress frame whose
/// message is `key <api_key>`, then the answer. Returns its URL.
async fn progress_echo_server(calls: Calls) -> String {
    let app = axum::Router::new().fallback(move |body: axum::body::Bytes| {
        let calls = Arc::clone(&calls);
        async move {
            let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let Some(id) = request.get("id").cloned() else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let answer = |result: Value| {
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
            };
            match request["method"].as_str() {
                Some("initialize") => answer(json!({"protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}}, "serverInfo": {"name": "echoes", "version": "0"}})),
                Some("tools/list") => answer(json!({"tools": [
                    {"name": "echo", "description": "fixture", "inputSchema": {"type": "object"}}
                ]})),
                Some("tools/call") => {
                    let params = request["params"].clone();
                    calls.lock().push(params.clone());
                    let key = params["arguments"]["api_key"].as_str().unwrap_or_default();
                    let progress = json!({"jsonrpc": "2.0", "method": "notifications/progress",
                        "params": {"progressToken": params["_meta"]["progressToken"],
                                   "progress": 1, "message": format!("key {key}")}});
                    let done = json!({"jsonrpc": "2.0", "id": id,
                        "result": {"content": [{"type": "text", "text": "done"}]}});
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                        format!("event: message\ndata: {progress}\n\nevent: message\ndata: {done}\n\n"),
                    )
                        .into_response()
                }
                _ => answer(json!({})),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let address = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/mcp")
}

/// [`router_on`] an HTTP backend served by [`progress_echo_server`].
async fn http_fixture() -> (axum::Router, Calls, FixtureDir) {
    let calls = Calls::default();
    let url = progress_echo_server(Arc::clone(&calls)).await;
    let (router, store) = router_on(TransportConfig::Http {
        http_url: url,
        streamable_http: Some(true),
        protocol_version: None,
    })
    .await;
    (router, calls, store)
}

/// The one call the HTTP backend received carried the injected secret.
fn injected_once(calls: &Calls, body: &str) {
    let calls = calls.lock();
    let [call] = calls.as_slice() else {
        panic!("premise: one call reached the backend: {body}");
    };
    assert_eq!(
        call["arguments"]["api_key"], SECRET,
        "premise: the gateway injected the secret: {body}"
    );
}

/// An HTTP backend's progress frame echoing the secret reaches the meta
/// route's client with the marker in its place.
#[tokio::test]
async fn an_http_backend_progress_echo_reaches_the_client_redacted() {
    let (router, calls, _store) = http_fixture().await;
    let body = meta_call(&router).await;
    injected_once(&calls, &body);
    assert_eq!(the_progress_message(&body), REDACTED_LINE, "{body}");
    assert!(
        !body.contains(SECRET),
        "the injected secret reached the client: {body}"
    );
}

/// The per-backend route discards a backend's notifications: the progress
/// frame never reaches its client, while the answer does.
#[tokio::test]
async fn the_per_backend_route_delivers_no_backend_notification() {
    let (router, calls, _store) = http_fixture().await;
    let body = direct_call(&router).await;
    injected_once(&calls, &body);
    assert_dropped(&body, "done");
}

/// One `echo` call on the per-backend route, carrying the client's progress
/// token `p1`; the whole body, whatever its encoding.
async fn direct_call(router: &axum::Router) -> String {
    post_stream(
        router,
        "/mcp/echoes",
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "echo", "arguments": {"q": "hi"}, "_meta": {"progressToken": "p1"}
        }}),
    )
    .await
}

/// The answer arrived (it holds `answered`), and no notification of any
/// method, in any encoding, nor the secret, came with it.
fn assert_dropped(body: &str, answered: &str) {
    assert!(
        body.contains(answered),
        "premise: the call was answered: {body}"
    );
    assert!(
        !body.contains("notifications/"),
        "a backend notification reached the per-backend client: {body}"
    );
    assert!(
        !body.contains(SECRET),
        "the injected secret reached the client: {body}"
    );
}

/// A stdio MCP child whose `echo` call writes a progress line, message
/// `key <api_key>`, before its answer.
#[cfg(unix)]
const STDIO_PROGRESS_ECHO: &str = r#"import json, sys
for line in sys.stdin:
    req = json.loads(line)
    if "id" not in req:
        continue
    method = req.get("method")
    if method == "initialize":
        body = {"result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                           "serverInfo": {"name": "echoes", "version": "0"}}}
    elif method == "tools/list":
        body = {"result": {"tools": [{"name": "echo", "description": "fixture",
                                      "inputSchema": {"type": "object"}}]}}
    elif method == "tools/call":
        params = req.get("params", {})
        token = params.get("_meta", {}).get("progressToken")
        key = params.get("arguments", {}).get("api_key", "")
        note = {"progressToken": token, "progress": 1, "message": "key " + key}
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": note}),
              flush=True)
        body = {"result": {"content": [{"type": "text", "text": "done"}]}}
    else:
        body = {"result": {}}
    print(json.dumps({"jsonrpc": "2.0", "id": req["id"], **body}), flush=True)
"#;

/// A stdio backend's progress line echoing the secret reaches the meta
/// route's client with the marker in its place. The child writes whatever
/// `api_key` it received, so `key [redacted]` shows the secret was injected
/// and then removed.
#[cfg(unix)]
#[tokio::test]
async fn a_stdio_backend_progress_echo_reaches_the_client_redacted() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let script = dir.path().join("echo.py");
    std::fs::write(&script, STDIO_PROGRESS_ECHO).expect("write the child script");
    let (router, _store) = router_on(TransportConfig::Stdio {
        command: format!("python3 {}", script.display()),
        cwd: None,
        protocol_version: None,
    })
    .await;
    let body = meta_call(&router).await;
    assert!(body.contains("done"), "premise: the child answered: {body}");
    assert_eq!(the_progress_message(&body), REDACTED_LINE, "{body}");
    assert!(
        !body.contains(SECRET),
        "the stdio echo reached the client: {body}"
    );
}

/// A WebSocket backend's progress frame quoting the call's arguments reaches
/// the meta route's client with the marker in place of the secret.
#[tokio::test]
async fn a_websocket_backend_progress_echo_reaches_the_client_redacted() {
    use crate::transport::websocket_test_server::{Behaviour, WsPeer};
    let peer = WsPeer::start(Behaviour::EchoInProgress).await;
    let (router, _store) = router_on(TransportConfig::WebSocket {
        ws_url: peer.url.clone(),
        protocol_version: None,
    })
    .await;
    let body = meta_call(&router).await;
    {
        let calls = peer.seen.calls.lock();
        let [call] = calls.as_slice() else {
            panic!("premise: one call reached the peer: {body}");
        };
        assert_eq!(
            call["params"]["arguments"]["api_key"], SECRET,
            "premise: the gateway injected the secret: {body}"
        );
    }
    let message = the_progress_message(&body);
    assert!(
        message.contains(r#""api_key":"[redacted]""#),
        "the echo was dropped, not redacted: {message}"
    );
    assert!(
        !body.contains(SECRET),
        "the WebSocket echo reached the client: {body}"
    );
}

/// The per-backend route drops a stdio backend's progress too: it reaches the
/// call's collected sink, which nothing reads.
#[cfg(unix)]
#[tokio::test]
async fn the_per_backend_route_drops_a_stdio_backends_notification() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let script = dir.path().join("echo.py");
    std::fs::write(&script, STDIO_PROGRESS_ECHO).expect("write the child script");
    let (router, _store) = router_on(TransportConfig::Stdio {
        command: format!("python3 {}", script.display()),
        cwd: None,
        protocol_version: None,
    })
    .await;
    assert_dropped(&direct_call(&router).await, "done");
}

/// The per-backend route drops a WebSocket backend's progress too.
#[tokio::test]
async fn the_per_backend_route_drops_a_websocket_backends_notification() {
    use crate::transport::websocket_test_server::{Behaviour, WsPeer};
    let peer = WsPeer::start(Behaviour::EchoInProgress).await;
    let (router, _store) = router_on(TransportConfig::WebSocket {
        ws_url: peer.url.clone(),
        protocol_version: None,
    })
    .await;
    let body = direct_call(&router).await;
    assert_eq!(
        peer.seen.calls.lock().len(),
        1,
        "premise: the peer was called: {body}"
    );
    assert_dropped(&body, "wire_id");
}
