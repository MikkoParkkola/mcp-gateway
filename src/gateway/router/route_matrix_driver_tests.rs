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
#[path = "route_matrix_driver_step_tests.rs"]
mod step;
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

/// What [`invoke_relay_then_resend`] saw.
pub(crate) struct RelayResend {
    /// The relay refusal.
    pub(crate) relayed: Value,
    /// The clean re-send under the refused nonce.
    pub(crate) resent: Value,
    /// A third send under that nonce.
    pub(crate) third: Value,
    /// Tool-list fills admitted on the target across the relayed call.
    pub(crate) fills: u64,
    /// Backend `tools/call` sends made by the clean re-send.
    pub(crate) resent_calls: usize,
}

/// R1, MIK-8150 NONCE.3: on the signed, relayed fixture whose backend answers
/// `text`, `k-std` reads it from `alpha` (the receipt, and the warm schema),
/// then `k-budget` relays it to `server` under nonce `b1` and is refused,
/// then re-sends a clean call under `b1`, then sends once more under it.
pub(crate) async fn invoke_relay_then_resend(text: &'static str, server: &str) -> RelayResend {
    let fx = super::direct_guards_fixture::fixture_signed_relayed(Answer::Text(text)).await;
    let read = signed_invoke(&fx, "k-std", "a1", serde_json::json!({})).await;
    assert!(read.get("error").is_none(), "premise: the read ran: {read}");
    let target = fx.state.backends.get(server).expect("fixture backend");
    let before = target.list_fills();
    let who = ("k-budget", server);
    let relayed = signed_invoke_on(&fx, who, "b1", serde_json::json!({ "cmd": text })).await;
    let fills = target.list_fills() - before;
    let sent = fx.calls.load(std::sync::atomic::Ordering::SeqCst);
    let resent = signed_invoke_on(&fx, who, "b1", serde_json::json!({})).await;
    let resent_calls = fx.calls.load(std::sync::atomic::Ordering::SeqCst) - sent;
    let third = signed_invoke_on(&fx, who, "b1", serde_json::json!({})).await;
    RelayResend {
        relayed,
        resent,
        third,
        fills,
        resent_calls,
    }
}

/// R3, R20: on the signed fixture with a spend budget, `k-budget` runs once
/// under `n1`, is refused by the budget under `n2`, re-sends under `n2`, then
/// re-sends under `n1`. Returns (the spend refusal, the `n2` re-send, the `n1`
/// re-send, the backend's `tools/call` count).
#[cfg(feature = "cost-governance")]
pub(crate) async fn direct_spend_then_resend() -> (Value, Value, Value, usize) {
    use super::direct_continuation_tests::{budget, signed_call};
    let fx =
        super::direct_guards_fixture::fixture_hardened_signed_built(Answer::Ok, true, budget).await;
    let who = ("k-budget", "alpha");
    let (_, first) = signed_call(&fx, who, "n1", serde_json::json!({})).await;
    assert!(
        first.get("error").is_none(),
        "premise: the first call ran: {first}"
    );
    let (_, refused) = signed_call(&fx, who, "n2", serde_json::json!({})).await;
    let (_, again) = signed_call(&fx, who, "n2", serde_json::json!({})).await;
    // Control: the first call's nonce was admitted, so its re-send is a replay.
    let (_, replay) = signed_call(&fx, who, "n1", serde_json::json!({})).await;
    (refused, again, replay, fx.calls.load(Ordering::SeqCst))
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

/// R4a: a modern task-augmented `tools/call read` by its surfaced name on
/// `/mcp`, declaring form elicitation, where `read` is listed
/// `destructiveHint: true`, so X14 has a destructive call to decide. `k-std`
/// carries no verified identity, so X14 binds it by its key (MIK-8137).
///
/// The whole round on one gateway: `k-std`'s call; its challenge, answered
/// `accept` and presented by another key (`k-budget`); then by `k-std`. With
/// the backend calls counted after each.
pub(crate) async fn task_submit_surfaced() -> TaskConfirmRound {
    let (fx, calls, params) = task_submit_fixture(Surfacing::On).await;
    let send = |key: &'static str, params: serde_json::Value| {
        super::direct_guards_fixture::send_with_headers(
            &fx,
            "/mcp",
            key,
            "tools/call",
            params,
            None,
            &TASK_SUBMIT_HEADERS,
        )
    };
    let (_, challenge) = send("k-std", params.clone()).await;
    let mut accepted = params;
    if let (Some(state), Some((issued, _))) = (
        challenge.pointer("/result/requestState").cloned(),
        challenge
            .pointer("/result/inputRequests")
            .and_then(serde_json::Value::as_object)
            .and_then(|requests| requests.iter().next()),
    ) {
        accepted["requestState"] = state;
        accepted["inputResponses"] = serde_json::json!({ issued.clone(): {"action": "accept"} });
    }
    let (_, other_key) = send("k-budget", accepted.clone()).await;
    let after_other_key = calls.load(Ordering::SeqCst);
    let (_, same_key) = send("k-std", accepted).await;
    TaskConfirmRound {
        challenge,
        other_key,
        after_other_key,
        same_key,
    }
}

/// [`task_submit_surfaced`]'s answers.
pub(crate) struct TaskConfirmRound {
    /// `k-std`'s first call: X14's question.
    pub challenge: serde_json::Value,
    /// The accepted answer presented by another key.
    pub other_key: serde_json::Value,
    /// Backend calls once that presentation was answered.
    pub after_other_key: usize,
    /// The accepted answer presented by `k-std`.
    pub same_key: serde_json::Value,
}

/// Whether the fixture surfaces `read` (P3, MIK-8326).
#[derive(Clone, Copy)]
pub(crate) enum Surfacing {
    /// `read` is surfaced on `/mcp`.
    On,
    /// Nothing is surfaced, so the name `read` matches no tool.
    Off,
}

/// The modern era's header mirrors for a `tools/call read`.
pub(super) const TASK_SUBMIT_HEADERS: [(&str, &str); 3] = [
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "read"),
];

/// The R4a fixture, surfacing `read` per `surfacing_mode`, with its backend
/// call counter and the task-augmented call's params.
async fn task_submit_fixture(
    surfacing_mode: Surfacing,
) -> (
    super::direct_guards_fixture::Fx,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    serde_json::Value,
) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = std::sync::Arc::new(Destructive {
        calls: std::sync::Arc::clone(&calls),
    });
    let fx = match surfacing_mode {
        Surfacing::On => super::direct_guards_fixture::fixture_built_on(transport, surfacing).await,
        Surfacing::Off => {
            super::direct_guards_fixture::fixture_built_on(transport, |meta| meta).await
        }
    };
    (fx, calls, task_submit_params())
}

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

/// One R4a call sent with the API key `key`, on a fixture that surfaces
/// `read` per `surfacing_mode`. Returns the HTTP status with the answer.
/// `k-deny` is the fixture's key denied `read` (P3, MIK-8326).
pub(crate) async fn task_submit_read_as(
    key: &str,
    surfacing_mode: Surfacing,
) -> (axum::http::StatusCode, Sent) {
    let (fx, calls, params) = task_submit_fixture(surfacing_mode).await;
    let (status, body) = super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        key,
        "tools/call",
        params,
        None,
        &TASK_SUBMIT_HEADERS,
    )
    .await;
    let sent = Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
        seen: Vec::new(),
    };
    (status, sent)
}

/// R4a `Authorize` (MIK-8315): a modern task-augmented `gateway_invoke` of a
/// personal capability the caller holds no grant for, on `/mcp`. Panics
/// unless the submit answers the sync call's status, code and message,
/// writes the sync call's audit records, creates no task and reaches nothing.
pub(crate) async fn task_submit_ungranted() {
    super::tests::task_execution_adapter::submit_authz::matrix_ungranted_invoke_submit().await;
}

/// R4a `Authorize` before `TaskConfirm` (MIK-8331): a task call by a surfaced
/// name from a caller without the grant, and from a non-admin for an admin
/// capability, answers as the sync call with no X14 challenge, and X14 does
/// not classify the surfaced capability for an admitted scope. Panics
/// otherwise.
pub(crate) async fn task_submit_authorized_before_x14() {
    super::tests::task_execution_adapter::x14_authorize_order::matrix_authorize_precedes_x14()
        .await;
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

/// R2, MIK-8150 NONCE.4: on the hardened, signed fixture surfacing
/// `alpha/read`, a keyed surfaced-name call runs under `s1`; the key reused for
/// other arguments is refused by execution admission (409) under `s2`; the
/// honest call is re-sent under `s2` with its own key; then a third call under
/// `s2`. Returns (the admission refusal, the re-send, the third send, the
/// backend's `tools/call` count).
pub(crate) async fn surfaced_admission_then_resend() -> (Value, Value, Value, usize) {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    let fx =
        super::direct_guards_fixture::fixture_hardened_signed_built(Answer::Ok, true, surfacing)
            .await;
    let call = |key: &'static str, nonce: &'static str, args: Value| {
        let fx = &fx;
        async move {
            let params = serde_json::json!({ "name": "read", "arguments": args, "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                NONCE_META: nonce,
                IDEMPOTENCY_KEY_META: key,
            }});
            let headers = [
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "read"),
            ];
            super::direct_guards_fixture::send_with_headers(
                fx,
                "/mcp",
                "k-std",
                "tools/call",
                params,
                None,
                &headers,
            )
            .await
            .1
        }
    };
    let first = call("s-k1", "s1", serde_json::json!({})).await;
    assert!(
        first.get("error").is_none(),
        "premise: the first call ran: {first}"
    );
    let refused = call("s-k1", "s2", serde_json::json!({ "cmd": "other" })).await;
    let resent = call("s-k2", "s2", serde_json::json!({ "cmd": "other" })).await;
    let third = call("s-k3", "s2", serde_json::json!({ "cmd": "other" })).await;
    (refused, resent, third, fx.calls.load(Ordering::SeqCst))
}
