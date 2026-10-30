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

pub(super) type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

/// How the `echo` tool reflects the arguments it received.
#[derive(Clone, Copy)]
pub(super) enum Reply {
    /// The arguments, as JSON text, in the result.
    Echo,
    /// The secret spelled with a `\u` escape in the wire text: it decodes
    /// back to the secret.
    UnicodeEscaped,
    /// The secret straight after an escape (`\n`) in the wire text.
    AfterEscape,
    /// A non-2xx JSON-RPC refusal whose message and data quote the secret.
    Refusal,
    /// The value of the `X-Api-Key` header the call arrived with, in the
    /// result.
    EchoHeader,
    /// `structuredContent.n` is this number literal, written as given.
    Number(&'static str),
    /// An error whose `code` is the injected value as a string, which a
    /// typed parse of the answer cannot accept.
    CodeIsSecret,
    /// Clean text and keys beside one field that holds the injected value.
    MixedClean,
    /// The tool list describes `echo` with the rule's value in its text,
    /// before any call: only a needle known at registration can catch it.
    DescribeSecret,
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
pub(super) async fn echo_server(calls: Calls, reply: Reply) -> String {
    let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
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
                    {"name": "echo", "description": if let Reply::DescribeSecret = reply {
                        format!("fixture, key {SECRET}")
                    } else {
                        "fixture".to_owned()
                    }, "inputSchema": {"type": "object"}},
                    {"name": "read", "description": "fixture", "inputSchema": {"type": "object"}}
                ]})),
                Some("tools/call") => {
                    let params = request["params"].clone();
                    calls.lock().push(params.clone());
                    let key = params["arguments"]["api_key"].as_str().unwrap_or_default().to_owned();
                    let header = headers
                        .get("x-api-key")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
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
                        Reply::EchoHeader => {
                            answer(json!({"content": [{"type": "text", "text": format!("header {header}")}]}))
                        }
                        Reply::Number(literal) => wire(format!(
                            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"n"}}],"structuredContent":{{"n":{literal}}}}}}}"#
                        )),
                        Reply::CodeIsSecret => wire(format!(
                            r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":"{key}","message":"refused"}}}}"#
                        )),
                        Reply::DescribeSecret => answer(json!({"content": [{"type": "text", "text": "ok"}]})),
                        Reply::MixedClean => answer(json!({
                            "content": [{"type": "text", "text": "plain words, a/b c-d_e"}],
                            "structuredContent": {"keep me": "unchanged: x=1; y=2", "k": key}
                        })),
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
    fixture_with(
        reply,
        json!({"name": "echo-key", "value": SECRET, "inject_key": "api_key"}),
    )
    .await
}

/// [`fixture`] with `rule` as the backend's one secret rule.
async fn fixture_with(
    reply: Reply,
    rule: Value,
) -> (axum::Router, Calls, super::tests::FixtureDir) {
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), reply).await;
    let rule: crate::secret_injection::CredentialRule =
        serde_json::from_value(rule).expect("rule parses");
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
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
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

/// A header rule is the only injection: the backend echoes the header value
/// it received, and the client sees it redacted on both routes (T1.40).
#[tokio::test]
async fn an_echoed_header_secret_is_redacted_on_both_routes() {
    let rule = json!({
        "name": "echo-header", "value": SECRET,
        "inject_as": "header", "inject_key": "X-Api-Key"
    });
    let (router, _calls, _store) = fixture_with(Reply::EchoHeader, rule.clone()).await;
    let meta = post(
        &router,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}}
        }}),
    )
    .await;
    let (router, _calls, _store) = fixture_with(Reply::EchoHeader, rule).await;
    let direct = post_direct(&router).await;
    for (route, body) in [("meta", meta), ("per-backend", direct)] {
        let text = body.to_string();
        assert!(
            text.contains("header "),
            "premise: {route}: the echo answered: {body}"
        );
        assert!(
            !text.contains(SECRET),
            "{route}: the header secret reached the client: {body}"
        );
        assert!(text.contains(MARKER), "{route}: not redacted: {body}");
    }
}

/// The meta route's answer for a backend whose rule injects `value` and
/// which answers with `reply`.
async fn meta_answer_with(reply: Reply, value: &str) -> Value {
    let rule = json!({"name": "echo-key", "value": value, "inject_key": "api_key"});
    let (router, _calls, _store) = fixture_with(reply, rule).await;
    post(
        &router,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}}
        }}),
    )
    .await
}

/// A numeric secret echoed as a JSON number, without its leading zero or in
/// exponent form, is matched by value and redacted (T1.13).
#[tokio::test]
async fn a_numeric_secret_echoed_as_a_number_is_redacted() {
    for (value, literal, shown) in [
        ("0739154", "739154", "739154"),
        ("12345", "1.2345e4", "12345"),
    ] {
        let body = meta_answer_with(Reply::Number(literal), value).await;
        let text = body.to_string();
        assert!(body["result"].is_object(), "premise: answered: {body}");
        assert!(
            !text.contains(shown),
            "the number {literal} (secret {value}) reached the client: {body}"
        );
        assert!(text.contains(MARKER), "{literal}: not redacted: {body}");
    }
}

/// An answer whose `error.code` is the secret string fails a typed parse;
/// the error the client gets carries no part of the body (T1.20). A control:
/// green on the line (the parse error does not quote the body today); a
/// mutant whose parse-failure diagnostic quotes the body turns it red.
#[tokio::test]
async fn a_secret_error_code_never_reaches_the_client_through_a_parse_error() {
    let body = meta_answer(Reply::CodeIsSecret).await;
    assert!(
        !body.to_string().contains(SECRET),
        "the malformed answer's secret reached the client: {body}"
    );
}

/// Text and keys that hold no secret pass byte for byte; only the field that
/// holds it changes (T1.35).
#[tokio::test]
async fn text_without_a_secret_passes_unchanged() {
    let body = meta_answer(Reply::MixedClean).await;
    let text = body.to_string();
    assert!(
        !text.contains(SECRET),
        "the secret reached the client: {body}"
    );
    assert!(
        text.contains(MARKER),
        "the field holding it was not redacted: {body}"
    );
    for clean in ["plain words, a/b c-d_e", "keep me", "unchanged: x=1; y=2"] {
        assert!(
            text.contains(clean),
            "clean text changed: {clean:?} missing from {body}"
        );
    }
}

/// A tool description that carries the rule's value reaches the client's
/// tool list redacted, before any call has injected anything: the needle is
/// known when the backend is registered (T1.18).
#[tokio::test]
async fn a_secret_in_a_tool_description_is_redacted_before_any_call() {
    let (router, calls, _store) = fixture(Reply::DescribeSecret).await;
    let params = json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    }});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/echoes")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
            .unwrap_or(Value::Null);
    let text = body.to_string();
    assert!(calls.lock().is_empty(), "premise: no call was made: {body}");
    assert!(
        text.contains("echo"),
        "premise: the tool was listed: {body}"
    );
    assert!(
        !text.contains(SECRET),
        "the description's secret reached the client: {body}"
    );
    assert!(
        text.contains(MARKER),
        "the description was dropped, not redacted: {body}"
    );
}
