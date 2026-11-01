// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A legacy client's bridged exchange that fails on the backend's side is
//! answered with the bridge's own -32003, which wraps that failure: the
//! delivered error counts as the backend's, from a plan step's invocation
//! and from a single-tool `gateway_execute` alike.

use super::*;
use crate::gateway::delivery_facts;
use crate::gateway::health_metrics::RpcError;
use crate::protocol::{JsonRpcResponse, Origin};

/// Asks on the first `tools/call`; every later one fails as a backend
/// failure (the backend went away), never the gateway's own error.
struct AskThenGone {
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl crate::transport::Transport for AskThenGone {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"k1": {
                        "method": "elicitation/create",
                        "params": {"message": "Which account?",
                            "requestedSchema": {"type": "object"}}
                    }},
                    "requestState": "s1"
                }),
            ));
        }
        Err(crate::Error::Transport("the backend went away".into()))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A client that accepts every question it is shown.
struct Accepting;

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for Accepting {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> std::result::Result<serde_json::Value, crate::gateway::input_bridge::DeliveryError> {
        Ok(json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {}}}))
    }
}

fn asking_meta() -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "asker",
        crate::config::BackendConfig::r2_off(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(AskThenGone {
        calls: std::sync::atomic::AtomicUsize::new(0),
    }));
    let _ = registry.register(backend);
    MetaMcp::new(registry)
}

/// What the error count reads from the frame `error` is delivered as, after
/// `run` in one delivery: the production frame builder, then the production
/// finalising stamp.
async fn counted_marker<F>(run: F) -> (crate::Error, Option<RpcError>)
where
    F: std::future::Future<Output = crate::Result<serde_json::Value>>,
{
    delivery_facts::scope(async move {
        let error = run.await.expect_err("premise: the bridged exchange failed");
        let mut frame = JsonRpcResponse::of_error(Some(RequestId::Number(1)), &error);
        delivery_facts::stamp_folded(&mut frame);
        let marker = RpcError::of_frame(&frame);
        (error, marker)
    })
    .await
}

/// A legacy caller declaring form elicitation, answered by `channel`.
fn legacy_ctx(channel: &Accepting) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    let mut ctx = allow_all_ctx();
    ctx.era = crate::protocol::meta::Era::Legacy;
    ctx.input_capabilities = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
        }})),
        None,
    )
    .declared_capabilities();
    ctx.channel = channel;
    ctx
}

fn assert_bridged_backend_failure(error: &crate::Error, marker: Option<RpcError>) {
    assert_eq!(
        error.to_rpc_code(),
        -32003,
        "premise: the bridge's refusal: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("asked for input and the bridged exchange could not be completed"),
        "premise: the bridged exchange's -32003: {error}"
    );
    assert_eq!(
        marker.map(|m| m.origin),
        Some(Origin::BackendFailure),
        "the -32003 wraps the backend's failure and counts as it"
    );
}

/// N16, a plan step's invocation (`invoke_tool`, run as a step).
#[tokio::test]
async fn a_bridged_backend_failure_in_a_step_counts_as_the_backends() {
    let meta = asking_meta();
    let channel = Accepting;
    let ctx = legacy_ctx(&channel);
    let (error, marker) = counted_marker(meta.invoke_tool(
        &json!({"server": "asker", "tool": "book", "arguments": {}}),
        Some("session-bridged-origin"),
        &ctx,
    ))
    .await;
    assert_bridged_backend_failure(&error, marker);
}

/// N16, a single-tool `gateway_execute` delivering that step's error as its
/// own answer.
#[tokio::test]
async fn a_bridged_backend_failure_in_a_single_execute_counts_as_the_backends() {
    let meta = asking_meta();
    let channel = Accepting;
    let ctx = legacy_ctx(&channel);
    let (error, marker) = counted_marker(meta.code_mode_execute(
        &json!({"tool": "asker:book", "arguments": {}}),
        Some("session-bridged-execute"),
        &ctx,
    ))
    .await;
    assert_bridged_backend_failure(&error, marker);
}
