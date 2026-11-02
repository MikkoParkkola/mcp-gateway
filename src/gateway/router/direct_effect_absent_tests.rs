// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route does not record a declared effect yet: its recording
//! lands with the route's rebuild. Pinned, so the absence is a known state;
//! that change flips this row.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::decision_record::Effect;

const BACKEND: &str = "plain";
const TOOL: &str = "read";

/// A backend listing [`TOOL`] read-only and answering every call.
struct ReadOnlyPeer;

#[async_trait::async_trait]
impl crate::transport::Transport for ReadOnlyPeer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let result = if method == "tools/list" {
            json!({"tools": [{"name": TOOL, "inputSchema": {"type": "object"},
                "annotations": {"readOnlyHint": true}}]})
        } else {
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            result,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_call_records_no_declared_effect_yet() {
    let backend = Arc::new(crate::backend::Backend::new(
        BACKEND,
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(ReadOnlyPeer));
    let tool: crate::protocol::Tool = serde_json::from_value(json!({"name": TOOL,
        "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": true}}))
    .expect("tool");
    backend.prefill_tools_for_test(vec![tool]);
    backend.set_read_only_declared_for_test(&[TOOL]);
    // Premise: the slot holds evidence a recording route would read.
    assert_eq!(
        backend.declared_effect_for(None, TOOL),
        Some(Effect::ReadOnly)
    );
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "direct".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("the transparency log opens"),
    );
    meta.enable_transparency_log(Arc::clone(&log));
    let auth = crate::config::AuthConfig::default();
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = registry;
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    let router = super::create_router(state);

    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = router.oneshot(request).await.expect("an answer");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let answer: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "premise: allowed: {answer}"
    );
    assert!(
        answer.get("result").is_some(),
        "premise: delivered: {answer}"
    );

    let raw = std::fs::read_to_string(log_dir.path().join("audit.jsonl")).unwrap_or_default();
    let invocations: Vec<Value> = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .collect();
    let [invocation] = invocations.as_slice() else {
        panic!("premise: one invocation record: {invocations:?}");
    };
    let decision = &invocation["decision"];
    assert_eq!(
        decision["v"], 2,
        "premise: a version 2 record: {invocation}"
    );
    assert!(decision.get("declared_effect").is_none(), "{invocation}");
    assert!(
        decision.get("declared_effect_source").is_none(),
        "{invocation}"
    );
}
