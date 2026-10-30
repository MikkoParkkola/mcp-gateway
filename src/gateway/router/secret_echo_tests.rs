// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that echoes a secret the gateway injected into its call must not
//! hand that secret back to the caller: the resolved value is the gateway's
//! credential, not part of the backend's answer.
//!
//! The backend here reflects the arguments it received into its result text,
//! as an echo tool or an error message quoting the request would.
use axum::body::to_bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_backend;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

/// A value no ordinary answer contains, long enough to be redacted.
const SECRET: &str = "echo-secret-7f3a9c2e51d84b06";

type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

/// How the `echo` tool reflects the arguments it received.
#[derive(Clone, Copy)]
enum Reply {
    /// The arguments, as JSON text, in the result.
    Echo,
    /// The secret spelled with a `\u` escape in the wire text, parsed as a
    /// transport parses a frame: it decodes back to the secret.
    UnicodeEscaped,
    /// The secret straight after an escape (`\n`) in the wire text.
    AfterEscape,
    /// A JSON-RPC refusal whose message and data quote the secret, as a
    /// non-2xx peer refusal arrives (`Error::JsonRpc`).
    Refusal,
}

/// Serves one `echo` tool that reflects the arguments it received.
struct Echo {
    calls: Calls,
    reply: Reply,
}

/// A frame as the wire carries it, parsed as a transport parses it.
fn frame(text: &str) -> JsonRpcResponse {
    serde_json::from_str(text).expect("the fixture frame parses")
}

#[async_trait::async_trait]
impl crate::transport::Transport for Echo {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let result = match method {
            "tools/list" => json!({"tools": [{
                "name": "echo", "description": "fixture",
                "inputSchema": {"type": "object"}
            }]}),
            "tools/call" => {
                let params = params.unwrap_or(Value::Null);
                self.calls.lock().push(params.clone());
                let key = params["arguments"]["api_key"].as_str().unwrap_or_default();
                match self.reply {
                    Reply::Echo => {
                        let received = params["arguments"].to_string();
                        json!({"content": [{"type": "text", "text": format!("received {received}")}]})
                    }
                    Reply::UnicodeEscaped => {
                        let (first, rest) = key.split_at(1);
                        let escaped = format!("\\u{:04x}{rest}", u32::from(first.as_bytes()[0]));
                        return Ok(frame(&format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"key {escaped}"}}]}}}}"#
                        )));
                    }
                    Reply::AfterEscape => {
                        return Ok(frame(&format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"line\n{key}"}}]}}}}"#
                        )));
                    }
                    Reply::Refusal => {
                        return Err(crate::Error::JsonRpc {
                            code: -32602,
                            message: format!("bad api_key {key}"),
                            data: Some(json!({"received": key})),
                        });
                    }
                }
            }
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// An `echoes` backend whose `api_key` argument the gateway injects.
async fn fixture(reply: Reply) -> (axum::Router, Calls, super::tests::FixtureDir) {
    let calls = Calls::default();
    // The backend's own rule: since per-backend injection, the registry
    // stamps the resolver at registration and the send injects.
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(json!({
        "name": "echo-key", "value": SECRET, "inject_key": "api_key"
    }))
    .expect("rule parses");
    let backend = Arc::new(Backend::new(
        "echoes",
        BackendConfig {
            secrets: vec![rule],
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Echo {
        calls: Arc::clone(&calls),
        reply,
    }));
    backend
        .get_tools_for_binding(None, &[])
        .await
        .expect("the fixture lists its tools");
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
}
