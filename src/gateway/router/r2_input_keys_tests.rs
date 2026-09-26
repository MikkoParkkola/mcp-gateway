// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.SCHEMA.1 (R2): a tool call carrying argument keys the tool's
//! schema does not declare is refused on the Meta-MCP route and on the direct
//! route, before it reaches the backend.
//!
//! The backend's catalogue is warmed by a real `tools/list` through the same
//! slot the refusal reads, never seeded, and the wire records every
//! `tools/call`, so "refused" means the backend saw nothing.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_backend;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
use crate::protocol::{JsonRpcResponse, RequestId};

type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

/// Serves one `edit` tool and records each `tools/call` params object.
struct Wire {
    calls: Calls,
}

fn edit_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "edits": {"type": "array", "items": {"type": "object",
                "properties": {"oldText": {"type": "string"}, "newText": {"type": "string"}},
                "required": ["oldText", "newText"]}},
            "note": {"type": "string"},
            "count": {"type": "integer"}
        }
    })
}

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let result = match method {
            "tools/list" => json!({"tools": [{
                "name": "edit", "description": "fixture", "inputSchema": edit_schema()
            }]}),
            "tools/call" => {
                self.calls.lock().push(params.unwrap_or(Value::Null));
                json!({"content": [{"type": "text", "text": "done"}]})
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

struct Fixture {
    router: axum::Router,
    calls: Calls,
    _store: tempfile::TempDir,
}

/// One `edits` backend; `warm` lists its tools through the caller's slot.
async fn fixture(config: BackendConfig, warm: bool) -> Fixture {
    fixture_with(config, warm, None).await
}

/// Rebuilds the fixture's Meta-MCP over the same registry.
type Customize =
    Box<dyn FnOnce(crate::gateway::test_helpers::MetaMcp) -> crate::gateway::test_helpers::MetaMcp>;

async fn fixture_with(config: BackendConfig, warm: bool, customize: Option<Customize>) -> Fixture {
    let calls = Calls::default();
    let backend = Arc::new(Backend::new(
        "edits",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Wire {
        calls: Arc::clone(&calls),
    }));
    if warm {
        backend
            .get_tools_for_binding(None, &[])
            .await
            .expect("the fixture lists its tools");
    }
    let (mut state, store) = test_router_app_state_with_backend(backend).await;
    if let Some(customize) = customize {
        let state = Arc::get_mut(&mut state).expect("state is unique");
        let meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state.backends));
        state.meta_mcp = Arc::new(customize(meta));
    }
    Fixture {
        router: create_router(state),
        calls,
        _store: store,
    }
}

async fn post(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn invoke(arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": "edits", "tool": "edit", "arguments": arguments}
    }})
}

fn direct(arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 12, "method": "tools/call",
        "params": {"name": "edit", "arguments": arguments}})
}

fn nested_invented() -> Value {
    json!({"edits": [{"oldText": "a", "newText": "b", "type": "replace"}]})
}

/// The tool result the caller sees. `gateway_invoke` carries the backend's
/// result as JSON text inside its own envelope, as it does for a capability
/// refusal; the direct route returns it as the JSON-RPC result itself.
fn tool_result(body: &Value) -> Value {
    body["result"]["content"][0]["text"]
        .as_str()
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .filter(|inner| inner.get("isError").is_some())
        .unwrap_or_else(|| body["result"].clone())
}

fn is_error(body: &Value) -> bool {
    tool_result(body)["isError"] == json!(true)
}

fn is_refusal(body: &Value) -> bool {
    let result = tool_result(body);
    result["isError"] == json!(true)
        && result["content"][0]["text"]
            .as_str()
            .is_some_and(|t| t.contains("edits[0].type"))
}

/// R2-T2: `gateway_invoke` with a nested invented key is refused.
#[tokio::test]
async fn meta_invoke_refuses_nested_invented_key() {
    let fx = fixture(BackendConfig::default(), true).await;
    let (status, body) = post(&fx.router, "/mcp", invoke(&nested_invented())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(is_refusal(&body), "not refused: {body}");
    assert!(fx.calls.lock().is_empty(), "the backend saw the call");
}

/// R2-T6: a top-level invented key is refused on the Meta-MCP route.
#[tokio::test]
async fn mcp_top_level_invented_key_refused() {
    let fx = fixture(BackendConfig::default(), true).await;
    let (_, body) = post(
        &fx.router,
        "/mcp",
        invoke(&json!({"edits": [], "exfil": 1})),
    )
    .await;
    assert!(is_error(&body), "{body}");
    assert!(fx.calls.lock().is_empty(), "the backend saw the call");
}

/// R2-T3: the direct route refuses with a tool result on the caller's id,
/// passthrough or not.
#[tokio::test]
async fn direct_route_refuses_nested_invented_key() {
    for passthrough in [false, true] {
        let config = BackendConfig {
            passthrough,
            ..BackendConfig::default()
        };
        let fx = fixture(config, true).await;
        let (status, body) = post(&fx.router, "/mcp/edits", direct(&nested_invented())).await;
        assert_eq!(status, StatusCode::OK, "passthrough={passthrough}: {body}");
        assert_eq!(body["id"], json!(12), "{body}");
        assert!(is_refusal(&body), "passthrough={passthrough}: {body}");
        assert!(fx.calls.lock().is_empty(), "passthrough={passthrough}");
    }
}

/// R2-T11 (route half): `off` forwards the invented key.
#[tokio::test]
async fn enforcement_off_forwards_invented_keys() {
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Off,
        ..BackendConfig::default()
    };
    let fx = fixture(config, true).await;
    let (_, body) = post(&fx.router, "/mcp/edits", direct(&nested_invented())).await;
    assert!(!is_error(&body), "{body}");
    assert_eq!(fx.calls.lock().len(), 1);
}

/// R2-T13, rewritten by F13 (design §5): a cold slot, three rows. `closed`
/// lists once and refuses; `standard` with a failing list forwards; `off`
/// forwards without listing. Red on base in the `closed` row only.
#[tokio::test]
async fn cold_slot_forwards_and_counts() {
    use super::f13_fetch_on_miss_tests::{ListMode, cold};
    let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
    let (_, body) = post(&fx.router, "/mcp/edits", direct(&nested_invented())).await;
    assert!(is_refusal(&body), "closed: {body}");
    assert_eq!((fx.rec.lists(), fx.rec.calls()), (1, 0), "closed");

    let fx = cold(InputSchemaEnforcement::Standard, ListMode::Fail).await;
    let (_, body) = post(&fx.router, "/mcp/edits", direct(&nested_invented())).await;
    assert!(!is_error(&body), "standard: {body}");
    assert_eq!(fx.rec.calls(), 1, "standard must forward on a failed list");

    let fx = cold(InputSchemaEnforcement::Off, ListMode::Serve).await;
    let (_, body) = post(&fx.router, "/mcp/edits", direct(&nested_invented())).await;
    assert!(!is_error(&body), "off: {body}");
    assert_eq!(
        (fx.rec.lists(), fx.rec.calls()),
        (0, 1),
        "off must not fetch"
    );
}

/// N3: a valid call reaches the backend with the caller's own arguments,
/// not a coerced copy (`null` kept, `"5"` not rewritten to 5).
#[tokio::test]
async fn mcp_args_forwarded_byte_identical() {
    let fx = fixture(BackendConfig::default(), true).await;
    let args = json!({"edits": [], "note": null, "count": "5"});
    let (_, body) = post(&fx.router, "/mcp", invoke(&args)).await;
    assert!(!is_error(&body), "{body}");
    let calls = fx.calls.lock();
    assert_eq!(calls.len(), 1, "{body}");
    assert_eq!(calls[0]["arguments"], args);
}

/// N2: a key the gateway injects is not the caller's, and is never refused.
#[tokio::test]
async fn injected_secret_key_not_refused() {
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(json!({
        "name": "k", "value": "s3cret", "inject_key": "api_key"
    }))
    .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(
        [("edits".to_string(), vec![rule])].into_iter().collect(),
    );
    let customize: Customize = Box::new(move |meta| meta.with_secret_injector(injector));
    let fx = fixture_with(BackendConfig::default(), true, Some(customize)).await;
    let (_, body) = post(&fx.router, "/mcp", invoke(&json!({"edits": []}))).await;
    assert!(!is_error(&body), "{body}");
    let calls = fx.calls.lock();
    assert_eq!(calls.len(), 1, "{body}");
    assert!(
        calls[0]["arguments"].get("api_key").is_some(),
        "{:?}",
        calls[0]
    );
}

/// R2-T17: a refused call is never dispatched: the invocation counter that
/// `accounted_dispatch` owns does not move.
#[cfg(feature = "metrics")]
#[test]
fn refused_call_is_not_counted_as_an_invocation() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (refused, valid) = telemetry_metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let fx = fixture(BackendConfig::default(), true).await;
            let (_, refused) = post(&fx.router, "/mcp", invoke(&nested_invented())).await;
            let before = handle.render();
            let (_, valid) = post(&fx.router, "/mcp", invoke(&json!({"edits": []}))).await;
            (refused, (before, valid))
        })
    });
    assert!(is_refusal(&refused), "{refused}");
    let (before, valid) = valid;
    assert!(!is_error(&valid), "{valid}");
    let counted = |text: &str| {
        text.lines()
            .any(|l| l.starts_with("mcp_tool_invocations_total"))
    };
    assert!(!counted(&before), "the refusal was counted: {before}");
    assert!(
        counted(&handle.render()),
        "the counter is not observable here"
    );
}

/// R2-T13 (counter half), rewritten by F13 (design §5): under `standard`, a
/// cold slot whose list fails is forwarded and counted `input_schema_unknown`.
#[cfg(feature = "metrics")]
#[test]
fn cold_slot_forward_is_counted() {
    use super::f13_fetch_on_miss_tests::{ListMode, cold, kind_counted, metered};
    let (calls, rendered) = metered(async {
        let fx = cold(InputSchemaEnforcement::Standard, ListMode::Fail).await;
        let _ = post(&fx.router, "/mcp/edits", direct(&nested_invented())).await;
        fx.rec.calls()
    });
    assert_eq!(calls, 1, "a cold slot must forward under standard");
    assert!(
        kind_counted(&rendered, concat!("input_schema_", "unknown")),
        "the unchecked forward was not counted: {rendered}"
    );
}

/// R2-T5: a code-mode chain whose first step invents a nested key stops
/// there; the valid second step is never dispatched.
#[tokio::test]
async fn code_mode_chain_step_refuses_invented_key() {
    let customize: Customize = Box::new(|meta| meta.with_code_mode(true));
    let fx = fixture_with(BackendConfig::default(), true, Some(customize)).await;
    let chain = json!({"chain": [
        {"tool": "edits:edit", "arguments": nested_invented()},
        {"tool": "edits:edit", "arguments": {"edits": []}}
    ]});
    let body = json!({"jsonrpc": "2.0", "id": 13, "method": "tools/call",
        "params": {"name": "gateway_execute", "arguments": chain}});
    let (_, body) = post(&fx.router, "/mcp", body).await;
    assert!(
        body.to_string().contains("edits[0].type"),
        "step 1 was not refused: {body}"
    );
    assert!(
        body.to_string()
            .contains("Chain step 0 (edits:edit) failed"),
        "the chain error does not name the failing step: {body}"
    );
    assert!(
        fx.calls.lock().is_empty(),
        "a chain step reached the backend: {body}"
    );
}
