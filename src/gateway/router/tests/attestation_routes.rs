// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.ATTEST.1: `enforce` holds on the HTTP routes, not only on
//! `gateway_invoke`.
//!
//! The direct `/mcp/{name}` route checks the token in
//! `_meta["io.mcp-gateway/attestation"]` and strips it before forwarding, on
//! sanitized and passthrough backends alike. A surfaced tool on `/mcp` carries
//! the same `_meta` token into the envelope the dispatch funnel checks.

use super::*;
use crate::attestation::{
    AttestationMode, AttestationValidator, BnautAttestationSigner, TokenRequest,
};
use crate::protocol::mrtr::ATTESTATION_META;

const KEY: &[u8] = b"route-attestation-key";
const TOOL: &str = "search";

/// Records the params of every forwarded request, so a test can assert both
/// that a refused call never dispatched and that a served one lost the token.
#[derive(Default)]
struct RecordingTransport {
    seen: Mutex<Vec<Option<Value>>>,
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            self.seen.lock().unwrap().push(params);
        }
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ))
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

fn token_for(tool: &str) -> String {
    BnautAttestationSigner::new(KEY.to_vec(), "route")
        .issue(
            &TokenRequest {
                agent_identity: "agent".to_string(),
                task_uuid: uuid::Uuid::new_v4(),
                capabilities: vec![tool.to_string()],
            },
            chrono::Utc::now(),
            chrono::TimeDelta::minutes(5),
        )
        .encoded()
        .to_string()
}

/// A router whose Meta-MCP has attestation in `mode` (or none), one backend
/// `demo` with a recording transport, and `TOOL` surfaced from it.
async fn router_with(
    mode: Option<AttestationMode>,
    passthrough: bool,
) -> (axum::Router, Arc<RecordingTransport>, tempfile::TempDir) {
    let (mut state, store) = test_router_app_state().await;
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig {
            passthrough,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RecordingTransport::default());
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);
    let _ = state.backends.register(backend);
    let mut meta =
        MetaMcp::new(Arc::clone(&state.backends)).with_surfaced_tools(vec![SurfacedToolConfig {
            server: "demo".to_string(),
            tool: TOOL.to_string(),
        }]);
    if let Some(mode) = mode {
        let validator = Arc::new(AttestationValidator::new(BnautAttestationSigner::new(
            KEY.to_vec(),
            "route",
        )));
        meta = meta.with_attestation(validator, mode);
    }
    Arc::get_mut(&mut state)
        .expect("the fixture state is not shared yet")
        .meta_mcp = Arc::new(meta);
    (create_router(state), transport, store)
}

/// POST one `tools/call` for `TOOL`, with the token in `_meta` when given.
async fn call(router: &axum::Router, uri: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut params = json!({"name": TOOL, "arguments": {"q": "x"}});
    if let Some(token) = token {
        params["_meta"] = json!({ (ATTESTATION_META): token });
    }
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// No forwarded request may carry the attestation key anywhere.
fn assert_token_never_forwarded(transport: &RecordingTransport) {
    for params in transport.seen.lock().unwrap().iter() {
        let text = params.as_ref().map(Value::to_string).unwrap_or_default();
        assert!(!text.contains(ATTESTATION_META), "forwarded: {text}");
    }
}

fn assert_refused(json: &Value, boundary: &str) {
    assert_eq!(json["error"]["code"], -32002, "{json}");
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains(boundary), "boundary label missing: {json}");
}

#[tokio::test]
async fn direct_route_enforce_rejects_missing_token() {
    let (router, transport, _store) = router_with(Some(AttestationMode::Enforce), false).await;
    let (_, json) = call(&router, "/mcp/demo", None).await;
    assert_refused(&json, "direct_route");
    assert!(transport.seen.lock().unwrap().is_empty(), "no dispatch");
}

/// Positive control for the refusal above, and the strip on the sanitized arm.
#[tokio::test]
async fn direct_route_enforce_admits_valid_token() {
    let (router, transport, _store) = router_with(Some(AttestationMode::Enforce), false).await;
    let (status, json) = call(&router, "/mcp/demo", Some(&token_for(TOOL))).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(json.get("error").is_none(), "{json}");
    assert_eq!(transport.seen.lock().unwrap().len(), 1, "one dispatch");
    assert_token_never_forwarded(&transport);
}

/// Passthrough skips sanitizing, never the strip: with enforce and with
/// attestation off, the backend does not see the token.
#[tokio::test]
async fn passthrough_backend_never_sees_token() {
    for mode in [Some(AttestationMode::Enforce), None] {
        let (router, transport, _store) = router_with(mode, true).await;
        let (status, json) = call(&router, "/mcp/demo", Some(&token_for(TOOL))).await;
        assert_eq!(status, StatusCode::OK, "{mode:?}: {json}");
        assert_eq!(transport.seen.lock().unwrap().len(), 1, "{mode:?}");
        assert_token_never_forwarded(&transport);
    }
}

#[tokio::test]
async fn passthrough_backend_enforce_rejects_missing_token() {
    let (router, transport, _store) = router_with(Some(AttestationMode::Enforce), true).await;
    let (_, json) = call(&router, "/mcp/demo", None).await;
    assert_refused(&json, "direct_route");
    assert!(transport.seen.lock().unwrap().is_empty(), "no dispatch");
}

/// A surfaced tool on `/mcp` under enforce: no `_meta` token is refused, a
/// valid one is accepted end to end and never reaches the backend.
#[tokio::test]
async fn surfaced_tool_enforce_carries_meta_token() {
    let (router, transport, _store) = router_with(Some(AttestationMode::Enforce), false).await;
    let (_, json) = call(&router, "/mcp", None).await;
    assert_refused(&json, "gateway_invoke");
    assert!(transport.seen.lock().unwrap().is_empty(), "no dispatch");

    let (status, json) = call(&router, "/mcp", Some(&token_for(TOOL))).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(json.get("error").is_none(), "{json}");
    assert_eq!(transport.seen.lock().unwrap().len(), 1, "one dispatch");
    assert_token_never_forwarded(&transport);
}

/// Observe never blocks, on either route.
#[tokio::test]
async fn observe_still_never_blocks() {
    let (router, transport, _store) = router_with(Some(AttestationMode::Observe), false).await;
    for uri in ["/mcp/demo", "/mcp"] {
        let (status, json) = call(&router, uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {json}");
        assert!(json.get("error").is_none(), "{uri}: {json}");
    }
    assert_eq!(transport.seen.lock().unwrap().len(), 2);
}
