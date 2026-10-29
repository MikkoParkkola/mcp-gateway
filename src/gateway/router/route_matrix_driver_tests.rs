// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only drivers for the route x check matrix (MIK-8137 family, b3).
//!
//! Each driver builds an existing router fixture and sends one backend
//! `tools/call` through that route's real entry point, nothing more. The
//! matrix (`gateway::route_check_matrix_tests`) owns every assertion.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::direct_guards_fixture::{Answer, post_direct, post_meta_invoke};
use crate::gateway::meta_mcp::MetaMcp;

/// MIK-8747: keyed calls across eras on one key.
#[path = "route_matrix_driver_era_tests.rs"]
pub(crate) mod era;
#[path = "route_matrix_driver_resend_tests.rs"]
mod resend;
#[path = "route_matrix_driver_response_tests.rs"]
pub(crate) mod response;
#[path = "route_matrix_driver_step_tests.rs"]
mod step;
#[path = "route_matrix_driver_task_tests.rs"]
mod task_submit;
#[cfg(feature = "cost-governance")]
pub(crate) use resend::direct_spend_then_resend;
pub(crate) use resend::{invoke_relay_then_resend, surfaced_admission_then_resend};
pub(crate) use task_submit::{
    Surfacing, task_submit_authorized_before_x14, task_submit_read_as, task_submit_surfaced,
    task_submit_ungranted,
};
#[path = "route_matrix_driver_trace_tests.rs"]
mod trace;
pub(crate) use super::direct_audit_tests::anon_intake::{NO_PRINCIPAL, keyed_no_principal_on};
pub(crate) use step::{
    playbook_as, playbook_budgeted, playbook_exposed, playbook_minting, playbook_then_task,
};
pub(crate) use trace::{audit_events, task_submit_traced};

/// What one call through a route produced.
pub(crate) struct Sent {
    /// The JSON-RPC body the client got.
    pub(crate) body: Value,
    /// How many `tools/call` sends reached the backend.
    pub(crate) backend_calls: usize,
    /// The params each of those sends carried.
    pub(crate) seen: Vec<Value>,
}

fn sent(fx: &super::direct_guards_fixture::Fx, body: Value) -> Sent {
    Sent {
        body,
        backend_calls: fx.calls.load(Ordering::SeqCst),
        seen: fx.seen.lock().expect("seen lock").clone(),
    }
}

/// R1 `/mcp` `gateway_invoke alpha read`, with the production firewall on both
/// layers writing audit rows to `audit`.
pub(crate) async fn invoke_firewalled(audit: &Path, args: Value) -> Sent {
    let fx =
        super::direct_guards_fixture::fixture_firewalled_audited(Answer::Ok, audit.to_path_buf())
            .await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read`, on the same firewalled fixture.
pub(crate) async fn direct_firewalled(audit: &Path, args: Value) -> Sent {
    let fx =
        super::direct_guards_fixture::fixture_firewalled_audited(Answer::Ok, audit.to_path_buf())
            .await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` with `security.sanitize_input` = `on`.
pub(crate) async fn invoke_sanitizing(on: bool, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_sanitizing(Answer::Ok, on).await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` with `security.sanitize_input` = `on`.
pub(crate) async fn direct_sanitizing(on: bool, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_sanitizing(Answer::Ok, on).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` on the firewalled fixture, whose
/// backend answers `text`.
pub(crate) async fn invoke_answering(text: &'static str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_with(Answer::Text(text), None, false)
        .await;
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        serde_json::json!({}),
        None,
        None,
    )
    .await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` on the firewalled fixture, whose backend
/// answers `text`.
pub(crate) async fn direct_answering(text: &'static str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_with(Answer::Text(text), None, false)
        .await;
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        serde_json::json!({}),
        None,
        None,
    )
    .await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` whose backend asks one elicitation
/// question the client never declared.
pub(crate) async fn invoke_asking() -> Sent {
    let fx = super::direct_guards_fixture::fixture(Answer::AskOnce, |_| {}).await;
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        serde_json::json!({}),
        None,
        None,
    )
    .await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` whose backend asks the same question.
pub(crate) async fn direct_asking() -> Sent {
    let fx = super::direct_guards_fixture::fixture(Answer::AskOnce, |_| {}).await;
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        serde_json::json!({}),
        None,
        None,
    )
    .await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` with a chain signer emitting on
/// request, the call carrying a chain nonce.
pub(crate) async fn invoke_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture(Answer::Ok, |meta| {
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
    })
    .await;
    let params = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": {} },
        "_meta": { NONCE_KEY: "matrix-nonce" },
    });
    let (_, body) =
        super::direct_guards_fixture::send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` with the same signer and nonce.
pub(crate) async fn direct_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture(Answer::Ok, |meta| {
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
    })
    .await;
    let params = serde_json::json!({
        "name": "read", "arguments": {}, "_meta": { NONCE_KEY: "matrix-nonce" },
    });
    let (_, body) =
        super::direct_guards_fixture::send(&fx, "/mcp/alpha", "k-std", "tools/call", params, None)
            .await;
    sent(&fx, body)
}

/// `alpha`'s `read` surfaced under its own name on the Meta-MCP.
pub(super) fn surfacing(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: "alpha".to_string(),
        tool: "read".to_string(),
    }])
}

/// `tools/call read` on `/mcp`: the surfaced-name route (R2), with `meta`
/// as the params' `_meta` when given.
async fn call_surfaced(
    fx: &super::direct_guards_fixture::Fx,
    args: Value,
    meta: Option<Value>,
) -> Value {
    let mut params = serde_json::json!({ "name": "read", "arguments": args });
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    super::direct_guards_fixture::send(fx, "/mcp", "k-std", "tools/call", params, None)
        .await
        .1
}

/// R2 with a chain signer emitting on request, the call carrying a chain nonce.
pub(crate) async fn surfaced_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture_built(Answer::Ok, |meta| {
        let mut meta = surfacing(meta);
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
        meta
    })
    .await;
    let body = call_surfaced(
        &fx,
        serde_json::json!({}),
        Some(serde_json::json!({ NONCE_KEY: "matrix-nonce" })),
    )
    .await;
    sent(&fx, body)
}

/// [`surfaced_chained`] whose backend answers `text` under the team-shared
/// context-integrity baseline, which withholds an injected instruction.
pub(crate) async fn surfaced_chained_gated(text: &'static str) -> Sent {
    use crate::context_integrity::{
        ContextIntegrityKernel, ContextIntegrityPolicy, ContextIntegrityPolicyPreset,
    };
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture_built(Answer::Text(text), |meta| {
        let mut meta = surfacing(meta);
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
        meta.set_context_integrity_kernel(ContextIntegrityKernel::new(
            ContextIntegrityPolicy::from_preset(ContextIntegrityPolicyPreset::TeamShared),
        ));
        meta
    })
    .await;
    let body = call_surfaced(
        &fx,
        serde_json::json!({}),
        Some(serde_json::json!({ NONCE_KEY: "matrix-nonce" })),
    )
    .await;
    sent(&fx, body)
}

/// R2 on the firewalled fixture writing audit rows to `audit`.
pub(crate) async fn surfaced_firewalled(audit: &Path, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited_built(
        Answer::Ok,
        audit.to_path_buf(),
        surfacing,
    )
    .await;
    let body = call_surfaced(&fx, args, None).await;
    sent(&fx, body)
}

/// The params of a modern `tools/call` of `name` declaring form elicitation,
/// extended by `extra`.
fn modern(name: &str, arguments: &Value, extra: &Value) -> Value {
    let mut params = serde_json::json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    params
}

/// A modern call on `uri` (`/mcp` or `/mcp/alpha`) of `name`.
async fn modern_call(
    fx: &super::direct_guards_fixture::Fx,
    uri: &str,
    (name, arguments): (&str, Value),
    extra: &Value,
) -> Value {
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    let params = modern(name, &arguments, extra);
    super::direct_guards_fixture::send_with_headers(
        fx,
        uri,
        "k-std",
        "tools/call",
        params,
        None,
        &headers,
    )
    .await
    .1
}

/// The backend asks one question on `uri`; the retry answers it with
/// `answer`, on the firewalled fixture writing audit rows to `audit`.
/// Returns the retry's outcome.
async fn retry_answering(audit: &Path, uri: &str, call: (&str, Value), answer: &str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited(
        Answer::AskOnce,
        audit.to_path_buf(),
    )
    .await;
    let asked = modern_call(&fx, uri, call.clone(), &serde_json::json!({})).await;
    let state = super::direct_continuation_tests::state_of(&asked);
    let retry = serde_json::json!({
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": answer}}},
    });
    let body = modern_call(&fx, uri, call, &retry).await;
    sent(&fx, body)
}

/// R2's retry form (MIK-8159.CHAIN.1): the backend asks through
/// `gateway_invoke`; the retry names `read` itself on `/mcp`, carrying a chain
/// nonce, with a chain signer emitting on request.
pub(crate) async fn retry_by_name_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture(Answer::AskOnce, |meta| {
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
    })
    .await;
    let invoke = serde_json::json!({ "server": "alpha", "tool": "read", "arguments": {} });
    let asked = modern_call(
        &fx,
        "/mcp",
        ("gateway_invoke", invoke),
        &serde_json::json!({}),
    )
    .await;
    let state = super::direct_continuation_tests::state_of(&asked);
    let retry = serde_json::json!({
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "acct-1"}}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
            NONCE_KEY: "matrix-nonce"
        },
    });
    let body = modern_call(&fx, "/mcp", ("read", serde_json::json!({})), &retry).await;
    sent(&fx, body)
}

/// R1: a continuation retry on `gateway_invoke` whose answer is `answer`.
pub(crate) async fn invoke_retry_answering(audit: &Path, answer: &str) -> Sent {
    let call = serde_json::json!({ "server": "alpha", "tool": "read", "arguments": {} });
    retry_answering(audit, "/mcp", ("gateway_invoke", call), answer).await
}

/// R3: the same retry on `/mcp/alpha` `read`.
pub(crate) async fn direct_retry_answering(audit: &Path, answer: &str) -> Sent {
    retry_answering(audit, "/mcp/alpha", ("read", serde_json::json!({})), answer).await
}

/// A hardened, signed `gateway_invoke read` on `/mcp` as `key` under `nonce`,
/// declaring form elicitation, with `args`.
async fn signed_invoke(
    fx: &super::direct_guards_fixture::Fx,
    key: &str,
    nonce: &str,
    args: Value,
) -> Value {
    signed_invoke_on(fx, (key, "alpha"), nonce, args).await
}

/// [`signed_invoke`] against `server`.
async fn signed_invoke_on(
    fx: &super::direct_guards_fixture::Fx,
    (key, server): (&str, &str),
    nonce: &str,
    args: Value,
) -> Value {
    let params = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": {"server": server, "tool": "read", "arguments": args, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    super::direct_guards_fixture::send_with_headers(
        fx,
        "/mcp",
        key,
        "tools/call",
        params,
        None,
        &headers,
    )
    .await
    .1
}

/// A backend listing `read` as `destructiveHint: true` and counting its sends.
pub(super) struct Destructive {
    pub(super) calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Destructive {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            serde_json::json!({"tools": [{
                "name": "read",
                "inputSchema": {"type": "object"},
                "annotations": {"destructiveHint": true, "readOnlyHint": false}
            }]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            serde_json::json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
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

/// The modern era's header mirrors for a `tools/call read`.
pub(super) const TASK_SUBMIT_HEADERS: [(&str, &str); 3] = [
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "read"),
];

/// The R4a task-augmented call's params.
fn task_submit_params() -> serde_json::Value {
    serde_json::json!({
        "name": "read",
        "arguments": {},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "elicitation": {"form": {}},
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "x14-submit"
        }
    })
}

/// A backend whose `tools/call` signals `entered`, then waits for `gate`
/// before answering: a call held in flight while a second one arrives.
struct Held {
    entered: std::sync::Arc<tokio::sync::Notify>,
    gate: std::sync::Arc<tokio::sync::Notify>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Held {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            serde_json::json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]})
        } else {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.gate.notified().await;
            serde_json::json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
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

/// Two R1 `gateway_invoke` calls under one idempotency key: the second is sent
/// while the first is held in flight at the backend. Returns (the second's answer, the backend's
/// `tools/call` count once both settled).
pub(crate) async fn concurrent_same_key() -> (Value, usize) {
    use std::sync::Arc;
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let held = Held {
        entered: Arc::clone(&entered),
        gate: Arc::clone(&gate),
        calls: Arc::clone(&calls),
    };
    let fx =
        Arc::new(super::direct_guards_fixture::fixture_firewalled_on(Arc::new(held), None).await);
    let call = |fx: Arc<super::direct_guards_fixture::Fx>| async move {
        let args = serde_json::json!({});
        post_meta_invoke(&fx, "k-std", "alpha", "read", args, Some("lease-1"), None)
            .await
            .1
    };
    let first = tokio::spawn(call(Arc::clone(&fx)));
    // Bounded: a first call that never reaches the backend fails the row
    // instead of hanging it.
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.notified())
        .await
        .expect("the first call reached the held backend");
    // Bounded too: on a lease miss the second call reaches the held backend
    // and waits on `gate`; release both before asserting so nothing hangs.
    let second =
        tokio::time::timeout(std::time::Duration::from_secs(30), call(Arc::clone(&fx))).await;
    gate.notify_waiters();
    gate.notify_one();
    let second = second.expect("the second call was answered while the first was held");
    let _first = tokio::time::timeout(std::time::Duration::from_secs(30), first)
        .await
        .expect("the first call finished once released")
        .expect("the first call did not panic");
    (second, calls.load(Ordering::SeqCst))
}
