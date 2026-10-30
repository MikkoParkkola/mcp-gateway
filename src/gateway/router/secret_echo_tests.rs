// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that echoes a secret the gateway injected into its call must not
//! hand that secret back to the caller: the resolved value is the gateway's
//! credential, not part of the backend's answer.
//!
//! The backend here is a real HTTP MCP server on a loopback port that
//! reflects the arguments it received, as an echo tool or an error message
//! quoting the request would. A real transport, not a mock: the secret is
//! removed where the transport parses the backend's bytes, which a mock
//! transport would never pass through.
use axum::body::to_bytes;
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_backend;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};

/// A value no ordinary answer contains.
const SECRET: &str = "echo-secret-7f3a9c2e51d84b06";

/// The marker an echoed secret is replaced with.
const MARKER: &str = "[redacted]";

type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

/// How the `echo` tool reflects the arguments it received.
#[derive(Clone, Copy)]
enum Reply {
    /// The arguments, as JSON text, in the result.
    Echo,
    /// The secret spelled with a `\u` escape in the wire text: it decodes
    /// back to the secret.
    UnicodeEscaped,
    /// The secret straight after an escape (`\n`) in the wire text.
    AfterEscape,
    /// A non-2xx JSON-RPC refusal whose message and data quote the secret.
    Refusal,
}

/// A frame's exact wire text, as the backend sends it.
fn wire(text: String) -> axum::response::Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        text,
    )
        .into_response()
}

/// A Streamable HTTP MCP server on a loopback port that lists one `echo`
/// tool and answers each call with `reply`; returns its URL.
async fn echo_server(calls: Calls, reply: Reply) -> String {
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
                Some("tools/list") => answer(json!({"tools": [{
                    "name": "echo", "description": "fixture", "inputSchema": {"type": "object"}
                }]})),
                Some("tools/call") => {
                    let params = request["params"].clone();
                    calls.lock().push(params.clone());
                    let key = params["arguments"]["api_key"].as_str().unwrap_or_default().to_owned();
                    match reply {
                        Reply::Echo => {
                            let received = params["arguments"].to_string();
                            answer(json!({"content": [{"type": "text", "text": format!("received {received}")}]}))
                        }
                        Reply::UnicodeEscaped => {
                            let (first, rest) = key.split_at(1);
                            let escaped = format!("\\u{:04x}{rest}", u32::from(first.as_bytes()[0]));
                            wire(format!(
                                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"key {escaped}"}}]}}}}"#
                            ))
                        }
                        Reply::AfterEscape => wire(format!(
                            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"line\n{key}"}}]}}}}"#
                        )),
                        Reply::Refusal => (
                            axum::http::StatusCode::BAD_REQUEST,
                            axum::Json(json!({"jsonrpc": "2.0", "id": id, "error": {
                                "code": -32602,
                                "message": format!("bad api_key {key}"),
                                "data": {"received": key}
                            }})),
                        )
                            .into_response(),
                    }
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

/// An `echoes` HTTP backend, served by [`echo_server`], whose own rule
/// injects [`SECRET`] as the `api_key` argument.
async fn fixture(reply: Reply) -> (axum::Router, Calls, super::tests::FixtureDir) {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), reply).await;
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(json!({
        "name": "echo-key", "value": SECRET, "inject_key": "api_key"
    }))
    .expect("rule parses");
    let backend = Arc::new(Backend::new(
        "echoes",
        BackendConfig {
            enabled: true,
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            secrets: vec![rule],
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(30),
    ));
    let (state, store) = test_router_app_state_with_backend(backend).await;
    (create_router(state), calls, store)
}

async fn post(router: &axum::Router, body: Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// On the meta route, a backend that echoes the injected secret does not get
/// it into the client's answer.
#[tokio::test]
async fn an_echoed_secret_does_not_reach_the_client_on_the_meta_route() {
    let (router, calls, _store) = fixture(Reply::Echo).await;
    let body = post(
        &router,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}}
        }}),
    )
    .await;
    {
        let calls = calls.lock();
        let [call] = calls.as_slice() else {
            panic!("premise: one call reached the backend: {body}");
        };
        assert_eq!(
            call["arguments"]["api_key"], SECRET,
            "premise: the gateway injected the secret"
        );
    }
    assert!(
        body["result"].is_object(),
        "premise: the call was answered: {body}"
    );
    assert!(
        !body.to_string().contains(SECRET),
        "the injected secret reached the client: {body}"
    );
    assert!(
        body.to_string().contains(MARKER),
        "the echo was dropped, not redacted: {body}"
    );
}

/// The meta route's answer to one `echo` call answered with `reply`, after
/// checking the backend received the injected secret.
async fn meta_answer(reply: Reply) -> Value {
    let (router, calls, _store) = fixture(reply).await;
    let body = post(
        &router,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}}
        }}),
    )
    .await;
    let calls = calls.lock();
    let [call] = calls.as_slice() else {
        panic!("premise: one call reached the backend: {body}");
    };
    assert_eq!(
        call["arguments"]["api_key"], SECRET,
        "premise: the gateway injected the secret"
    );
    body
}

/// A secret the wire spells with a `\u` escape decodes back to the secret,
/// and is redacted as the secret.
#[tokio::test]
async fn a_unicode_escaped_echo_does_not_reach_the_client() {
    let body = meta_answer(Reply::UnicodeEscaped).await;
    assert!(body["result"].is_object(), "premise: answered: {body}");
    assert!(
        !body.to_string().contains(SECRET),
        "the escaped secret reached the client: {body}"
    );
    assert!(body.to_string().contains(MARKER), "not redacted: {body}");
}

/// A secret straight after an escape in the wire text is redacted, and the
/// escape before it survives: the answer still carries its newline.
#[tokio::test]
async fn a_secret_after_an_escape_is_redacted_and_the_escape_kept() {
    let body = meta_answer(Reply::AfterEscape).await;
    assert!(body["result"].is_object(), "premise: answered: {body}");
    let text = body.to_string();
    assert!(
        !text.contains(SECRET),
        "the secret reached the client: {body}"
    );
    assert!(
        text.contains("line\\n"),
        "the escape before it was lost: {body}"
    );
    assert!(text.contains(MARKER), "not redacted: {body}");
}

/// A peer refusal whose message and data quote the secret (a non-2xx
/// JSON-RPC refusal) reaches the client without it.
#[tokio::test]
async fn a_refusal_quoting_the_secret_reaches_the_client_redacted() {
    let body = meta_answer(Reply::Refusal).await;
    assert!(
        !body.to_string().contains(SECRET),
        "the refusal carried the secret to the client: {body}"
    );
    assert!(body.to_string().contains(MARKER), "not redacted: {body}");
}

/// One `echo` call on the per-backend route `/mcp/echoes`, as a modern
/// client sends it.
async fn post_direct(router: &axum::Router) -> Value {
    let params = json!({"name": "echo", "arguments": {"q": "hi"}, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28"
    }});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/echoes")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "echo")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap_or(Value::Null)
}

/// The per-backend route's answer to one `echo` call answered with
/// `reply`, after checking the backend received the injected secret.
async fn direct_answer(reply: Reply) -> Value {
    let (router, calls, _store) = fixture(reply).await;
    let body = post_direct(&router).await;
    let calls = calls.lock();
    let [call] = calls.as_slice() else {
        panic!("premise: one call reached the backend: {body}");
    };
    assert_eq!(
        call["arguments"]["api_key"], SECRET,
        "premise: the gateway injected the secret on the per-backend route"
    );
    body
}

/// The per-backend route: the same four echoes, each redacted, never
/// dropped.
#[tokio::test]
async fn every_echo_is_redacted_on_the_per_backend_route() {
    for (reply, what) in [
        (Reply::Echo, "a plain echo"),
        (Reply::UnicodeEscaped, "a unicode-escaped echo"),
        (Reply::AfterEscape, "an echo after an escape"),
        (Reply::Refusal, "a refusal quoting the secret"),
    ] {
        let body = direct_answer(reply).await;
        let text = body.to_string();
        assert!(!text.contains(SECRET), "{what} reached the client: {body}");
        assert!(
            text.contains(MARKER),
            "{what} was dropped, not redacted: {body}"
        );
    }
}
