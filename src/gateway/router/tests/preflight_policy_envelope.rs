// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;
// Explicit: the glob above and the standard prelude both offer `assert_eq`,
// which is E0659 ambiguous in a child module until one of them is named.
use crate::attestation::{
    AttestationMode, AttestationValidator, BnautAttestationSigner, TokenRequest,
};
use axum::body::Body;
use axum::http::Request;
use chrono::{TimeDelta, Utc};
use pretty_assertions::assert_eq;
use uuid::Uuid;

const API_KEY: &str = "attestation-test-credential-0123456789";
const BACKEND: &str = "attestation_backend";
const TOOL: &str = "echo";
const SIGNING_KEY: &[u8] = b"preflight-policy-envelope-key";
const WRONG_SIGNING_KEY: &[u8] = b"preflight-policy-wrong-key-xxx";
const ISSUER: &str = "wiring";

struct EchoRecorder {
    url: String,
    received: Arc<Mutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl EchoRecorder {
    async fn start() -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let app_received = Arc::clone(&received);
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
                let received = Arc::clone(&app_received);
                async move {
                    received
                        .lock()
                        .expect("backend recorder")
                        .push(request.clone());
                    let id = request.get("id").cloned().unwrap_or(Value::Null);
                    let response = match request.get("method").and_then(Value::as_str) {
                        Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": BACKEND, "version": "test"}
                        }}),
                        Some("tools/list") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "tools": [{
                                "name": TOOL,
                                "description": "returns the configured test result",
                                "inputSchema": {"type": "object"},
                                "annotations": {"readOnlyHint": true}
                            }]
                        }}),
                        Some("tools/call") => json!({"jsonrpc": "2.0", "id": id, "result": {
                            "content": [{"type": "text", "text": "echo-ok"}]
                        }}),
                        Some("notifications/initialized") => json!({}),
                        _ => json!({"jsonrpc": "2.0", "id": id, "error": {
                            "code": -32601, "message": "fixture method not found"
                        }}),
                    };
                    axum::Json(response)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let address = listener.local_addr().expect("backend address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve backend");
        });
        Self {
            url: format!("http://{address}/"),
            received,
            task,
        }
    }

    fn tools_call_count(&self) -> usize {
        self.received
            .lock()
            .expect("backend recorder")
            .iter()
            .filter(|request| request["method"] == "tools/call")
            .count()
    }
}

impl Drop for EchoRecorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn validator() -> Arc<AttestationValidator> {
    Arc::new(AttestationValidator::new(BnautAttestationSigner::new(
        SIGNING_KEY.to_vec(),
        ISSUER,
    )))
}

fn issue_token(signing_key: &[u8], capabilities: Vec<String>) -> String {
    BnautAttestationSigner::new(signing_key.to_vec(), ISSUER)
        .issue(
            &TokenRequest {
                agent_identity: "agent-9".to_string(),
                task_uuid: Uuid::new_v4(),
                capabilities,
            },
            Utc::now(),
            TimeDelta::minutes(5),
        )
        .encoded()
        .to_string()
}

fn valid_token() -> String {
    issue_token(SIGNING_KEY, vec![TOOL.to_string()])
}

fn wrong_key_token() -> String {
    issue_token(WRONG_SIGNING_KEY, vec![TOOL.to_string()])
}

fn auth_config() -> AuthConfig {
    serde_json::from_value(json!({
        "enabled": true,
        "public_paths": ["/health"],
        "api_keys": [{
            "key": API_KEY,
            "name": "attestation-owner",
            "backends": [BACKEND]
        }]
    }))
    .expect("AuthConfig shape")
}

fn recording_backend_at(http_url: &str) -> Arc<Backend> {
    Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            transport: crate::config::TransportConfig::Http {
                http_url: http_url.to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn envelope_state(backend_url: &str) -> Arc<AppState> {
    let mut config = crate::config::Config::default();
    config.server.modern_protocol = true;
    let mut state = test_router_app_state_with(StreamingConfig::default(), config);
    {
        let inner = Arc::get_mut(&mut state).expect("unique AppState");
        inner.auth_config = Arc::new(ResolvedAuthConfig::from_config(&auth_config()));
        assert!(
            inner.backends.register(recording_backend_at(backend_url)),
            "the fixture backend must actually register"
        );
        inner.meta_mcp = Arc::new(
            MetaMcp::new(Arc::clone(&inner.backends))
                .with_attestation(validator(), AttestationMode::Enforce),
        );
    }
    state
}

fn invoke_request(id: &str, idempotency_key: &str, attestation: Option<&str>) -> Request<Body> {
    let mut arguments = json!({
        "server": BACKEND,
        "tool": TOOL,
        "arguments": {}
    });
    if let Some(token) = attestation {
        arguments["attestation"] = json!(token);
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": arguments,
            "_meta": {
                "io.mcp-gateway/idempotency-key": idempotency_key,
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(Body::from(serde_json::to_vec(&payload).expect("payload")))
        .expect("request")
}

async fn send(app: axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    // `axum::body::Body` is a stream, not a buffer: the id has to be read by
    // draining the body and then handing the SAME bytes back to the router.
    let (parts, request_body) = request.into_parts();
    let request_bytes = to_bytes(request_body, usize::MAX)
        .await
        .expect("request body");
    let expected_id = serde_json::from_slice::<Value>(&request_bytes)
        .expect("request payload")
        .get("id")
        .cloned()
        .expect("request carries a json-rpc id");
    let request = Request::from_parts(parts, Body::from(request_bytes.to_vec()));
    let response = app.oneshot(request).await.expect("oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("json-rpc");
    assert_eq!(
        body["id"], expected_id,
        "transport identity must be preserved"
    );
    assert_eq!(body["jsonrpc"], "2.0");
    (status, body)
}

fn assert_completed(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none() || body["error"].is_null(),
        "completed call must not carry json-rpc error: {body}"
    );
    assert!(
        body.get("result").is_some() && !body["result"].is_null(),
        "completed call must carry result: {body}"
    );
}

fn assert_attestation_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], json!(-32002));
    assert!(
        body.get("result").is_none() || body["result"].is_null(),
        "attestation refusal must not carry result: {body}"
    );
}

#[tokio::test]
async fn valid_keyed_modern_gateway_invoke_completes_and_same_key_retries_cached() {
    let backend = EchoRecorder::start().await;
    let app = create_router(envelope_state(&backend.url));
    let token = valid_token();
    let key = "envelope-valid-cached-key";

    let (status, body) = send(
        app.clone(),
        invoke_request("attestation-valid-1", key, Some(&token)),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);

    let (status, body) = send(
        app,
        invoke_request("attestation-valid-2", key, Some(&token)),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);
}

#[tokio::test]
async fn missing_token_refuses_minus_32002_before_cached_replay() {
    let backend = EchoRecorder::start().await;
    let app = create_router(envelope_state(&backend.url));
    let token = valid_token();
    let key = "envelope-missing-before-replay-key";

    let (status, body) = send(
        app.clone(),
        invoke_request("attestation-missing-seed", key, Some(&token)),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);

    let (status, body) = send(
        app.clone(),
        invoke_request("attestation-missing-denied", key, None),
    )
    .await;
    assert_attestation_refused(status, &body);
    assert_eq!(backend.tools_call_count(), 1);

    let (status, body) = send(
        app,
        invoke_request("attestation-missing-retry", key, Some(&token)),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);
}

#[tokio::test]
async fn wrong_key_token_refuses_minus_32002_before_cached_replay() {
    let backend = EchoRecorder::start().await;
    let app = create_router(envelope_state(&backend.url));
    let token = valid_token();
    let forged = wrong_key_token();
    let key = "envelope-wrong-key-before-replay-key";

    let (status, body) = send(
        app.clone(),
        invoke_request("attestation-wrong-seed", key, Some(&token)),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);

    let (status, body) = send(
        app.clone(),
        invoke_request("attestation-wrong-denied", key, Some(&forged)),
    )
    .await;
    assert_attestation_refused(status, &body);
    assert_eq!(backend.tools_call_count(), 1);

    let (status, body) = send(
        app,
        invoke_request("attestation-wrong-retry", key, Some(&token)),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);
}

#[tokio::test]
async fn same_valid_token_distinct_key_does_not_consume_attestation() {
    let backend = EchoRecorder::start().await;
    let app = create_router(envelope_state(&backend.url));
    let token = valid_token();

    let (status, body) = send(
        app.clone(),
        invoke_request(
            "attestation-reuse-a",
            "envelope-token-reuse-key-a",
            Some(&token),
        ),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 1);

    let (status, body) = send(
        app,
        invoke_request(
            "attestation-reuse-b",
            "envelope-token-reuse-key-b",
            Some(&token),
        ),
    )
    .await;
    assert_completed(status, &body);
    assert_eq!(backend.tools_call_count(), 2);
}
