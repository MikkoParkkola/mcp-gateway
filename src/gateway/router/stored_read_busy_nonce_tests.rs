// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 Busy parity, nonce hardening: only the gateway's sealed
//! transient answer asks for a signing nonce back, and the refund is
//! paid only when a step asked, no step dispatched, and the witness
//! survives (`signing.rs` `refund_due`). Shared signed helpers for the
//! busy-parity rows live here.
//!
//! No N2 row: every refund-ask site was checked (`invoke.rs` dispatch
//! admission, redeem, relay and chokepoint refusals and the transient
//! ask, the absent-name arm in `call_dispatch.rs`, and chain and
//! playbook steps, which dispatch through `invoke_tool`), and the only
//! signing dispatch mark is set in `invoke_tool_traced` immediately
//! after that send spends the witness. So an ask after a dispatch can
//! occur (a later chain step), but the witness is already spent, and
//! dropping the dispatched clause from `refund_due` changes no answer:
//! M7 is an equivalent mutant on today's paths, reported as such.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{BACKEND, Fx, KEY, TOOL, modern_meta, sole_operator};
use crate::config::SurfacedToolConfig;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    Binding, DirectAccountGateway,
};

/// The parent fixture with message signing armed (nonce required), a
/// local copy so the shared fixture keeps no signing config.
pub(super) async fn signed_fixture() -> Fx {
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, store) = super::super::tests::test_router_app_state_with_auth(&auth).await;
    let audit = tempfile::tempdir().expect("a log directory");
    let audit_path = audit.path().join("audit.jsonl");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: audit_path.to_string_lossy().into_owned(),
                key_id: "8392".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("open log"),
    );
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway
        .take_meta()
        .with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }]);
    meta.enable_transparency_log(Arc::clone(&log));
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"busy-parity-signing-secret-at-least-32-bytes".to_vec(),
            None,
            "busy-parity".into(),
        ),
        std::time::Duration::from_secs(300),
        true,
    );
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    Fx {
        router: super::super::create_router(Arc::clone(&state)),
        state,
        gateway,
        audit_path,
        _audit: audit,
        _store: store,
    }
}

/// A signed `gateway_invoke` of the operator's `read` under `nonce`
/// (the nonce rides in `arguments`, as `mcp_nonce_witness_tests` sends it).
pub(super) async fn signed_invoke(fx: &Fx, nonce: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL,
            "arguments": {"folder": "inbox"}, "nonce": nonce},
        "_meta": modern_meta(),
    }});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = fx.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// [`signed_invoke`] as a task-augmented keyed call (MIK-8392 G2c).
pub(super) async fn signed_task_invoke(fx: &Fx, nonce: &str, key: &str) -> Value {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL,
            "arguments": {"folder": "inbox"}, "nonce": nonce},
        "task": {}, "_meta": meta,
    }});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    let response = fx.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

pub(super) fn refused_as_replay(body: &Value) -> bool {
    body["error"]["message"]
        .as_str()
        .is_some_and(|m| m.to_lowercase().contains("replay"))
}

/// A backend that answers every `tools/call` with a JSON-RPC error shaped
/// exactly like the gateway's Busy answer, minus the gateway's seal
/// (scripted the way the neighbouring fixtures answer a JSON-RPC error:
/// an error response from the transport).
struct LookAlike {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for LookAlike {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        if method == "tools/list" {
            let tools = json!({"tools": [{"name": TOOL,
                "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}}]});
            return Ok(crate::protocol::JsonRpcResponse::success(id, tools));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::error_with_data(
            Some(id),
            -32603,
            "temporarily unavailable, retry",
            json!({"retryable": true}),
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

/// N1: a backend's look-alike error after a real dispatch does not earn a
/// nonce refund: the same signed request re-sent is refused as a replay
/// and nothing dispatches again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n1_a_backend_look_alike_after_a_dispatch_keeps_the_nonce() {
    let fx = signed_fixture().await;
    let calls = Arc::new(AtomicUsize::new(0));
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: DirectAccountGateway::operator_binding(),
            },
            Arc::new(LookAlike {
                calls: Arc::clone(&calls),
            }),
        );
    let first = signed_invoke(&fx, "n1-n1").await;
    assert!(
        first.get("error").is_some() || first["result"]["isError"] == true,
        "N1 premise: the backend's error answer, not a served result: {first}"
    );
    assert!(
        first.to_string().contains("temporarily unavailable, retry"),
        "N1 premise: the look-alike reached the caller as an error: {first}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "N1 premise: one real dispatch"
    );
    let resent = signed_invoke(&fx, "n1-n1").await;
    assert!(
        refused_as_replay(&resent),
        "N1: the nonce was given back after a dispatched look-alike: {resent}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "N1: the re-send dispatched again"
    );
}
