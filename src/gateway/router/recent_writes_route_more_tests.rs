// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Route rows R8, R10, R11 and R12 of the recent-write counter: what moves
//! `writes_total` through chains, playbooks, replays, refusals, retries and
//! backend errors. Observation: the delta of
//! `recent_writes().sample(now).writes_total`, exact and never sliding.
//! The fixture's `read` is undeclared, so it counts as a write.

use std::sync::atomic::Ordering;
use std::time::Instant;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture, post_direct, post_meta_invoke, send};

/// The counter's lifetime total on `meta`.
fn writes_total(meta: &crate::gateway::meta_mcp::MetaMcp) -> u64 {
    meta.recent_writes().sample(Instant::now()).writes_total
}

/// [`writes_total`] on the fixture's live `MetaMcp`.
fn total(fx: &Fx) -> u64 {
    writes_total(&fx.state.meta_mcp)
}

fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

/// A playbook `p` of two `alpha` `read` steps.
fn two_step_playbook() -> crate::playbook::PlaybookDefinition {
    let step =
        |name: &str| json!({"name": name, "tool": "read", "server": "alpha", "arguments": {}});
    serde_json::from_value(json!({
        "playbook": "1.0", "name": "p", "description": "two steps",
        "on_error": "abort", "steps": [step("s0"), step("s1")]
    }))
    .expect("the playbook deserialises")
}

/// R8: a code-mode chain of two counted steps moves the counter by two, and
/// so does a playbook of two counted steps: each leaf counts once, the
/// composite itself never.
#[tokio::test]
async fn r8_a_chain_and_a_playbook_of_two_steps_count_two() {
    let fx = fixture(Answer::Ok, |meta| {
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(two_step_playbook());
        meta.set_playbook_engine(engine);
    })
    .await;
    let chain = json!({"name": "gateway_execute", "arguments": {"chain": [
        {"tool": "alpha:read", "arguments": {}},
        {"tool": "alpha:read", "arguments": {}}
    ]}});
    let before = total(&fx);
    let (_, answer) = send(&fx, "/mcp", "k-std", "tools/call", chain, None).await;
    assert!(
        answer.get("error").is_none(),
        "premise: the chain ran: {answer}"
    );
    assert_eq!(calls(&fx), 2, "premise: both steps were sent: {answer}");
    assert_eq!(total(&fx) - before, 2, "chain: {answer}");

    let playbook = json!({"name": "gateway_run_playbook",
        "arguments": {"name": "p", "arguments": {}}});
    let before = total(&fx);
    let (_, answer) = send(&fx, "/mcp", "k-std", "tools/call", playbook, None).await;
    assert!(
        answer.get("error").is_none(),
        "premise: the playbook ran: {answer}"
    );
    assert_eq!(calls(&fx), 4, "premise: both steps were sent: {answer}");
    assert_eq!(total(&fx) - before, 2, "playbook: {answer}");
}

/// R10a: an idempotency replay is not counted. A keyed `gateway_invoke`
/// completes; its keyed repeat on `/mcp` and its keyed retry on `/mcp/alpha`
/// are both answered from the shared idempotency cache (mik8154 L3), the
/// backend runs once, and neither replay moves the counter.
#[tokio::test]
async fn r10a_an_idempotency_replay_is_not_counted() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let (_, first) =
        post_meta_invoke(&fx, "k-std", "alpha", "read", json!({}), Some("rw-k"), None).await;
    assert!(
        first.get("error").is_none(),
        "premise: the invoke ran: {first}"
    );
    assert_eq!(calls(&fx), 1, "premise: the invoke was sent: {first}");

    let before = total(&fx);
    let (_, again) =
        post_meta_invoke(&fx, "k-std", "alpha", "read", json!({}), Some("rw-k"), None).await;
    assert!(again.get("error").is_none(), "premise: replayed: {again}");
    let (_, retry) =
        post_direct(&fx, "alpha", "k-std", "read", json!({}), Some("rw-k"), None).await;
    assert!(retry.get("error").is_none(), "premise: replayed: {retry}");
    assert_eq!(
        calls(&fx),
        1,
        "premise: nothing was sent again: {again} {retry}"
    );
    assert_eq!(
        total(&fx) - before,
        0,
        "a replay was counted: {again} {retry}"
    );
}

/// R10b: a response-cache hit is not counted. The cache admits only tools the
/// backend declares read-only (`cache_admits`), and a read-only call never
/// counts, so this row guards the cache path only: it kills no
/// hook-placement mutant. Two `/mcp` calls of the declared `read` send once
/// (t23's control); the hit moves nothing.
#[cfg(feature = "webui")]
#[tokio::test]
async fn r10b_a_response_cache_hit_is_not_counted() {
    use super::ui_tool_call_tests::{ADMIN, Setup, fixture_with, invoke, post_mcp, sent};
    let fx = fixture_with(Setup::Cached).await;
    let first = post_mcp(&fx, ADMIN, invoke("read"), None).await;
    assert_eq!(sent(&fx), 1, "premise: the first call was sent");
    let before = writes_total(&fx.state.meta_mcp);
    let hit = post_mcp(&fx, ADMIN, invoke("read"), None).await;
    let hit = String::from_utf8_lossy(&hit);
    assert_eq!(
        sent(&fx),
        1,
        "premise: the cache answered: {} / {hit}",
        String::from_utf8_lossy(&first)
    );
    assert!(hit.contains("\"result\""), "premise: answered: {hit}");
    assert_eq!(writes_total(&fx.state.meta_mcp) - before, 0, "{hit}");
}

/// R10d: a web UI call the send point refuses (`admit_send`) is not counted.
/// No fixture setup refuses there, so the gate seam lets the UI deadline win
/// the race right after the gate admitted the call: `admit_send` then
/// refuses it, before hook 1. The tool is the undeclared `write`, which would
/// count if it were sent. Kills hook 1 moved above `admit_send`.
#[cfg(feature = "webui")]
#[tokio::test]
async fn r10d_a_call_refused_at_admit_send_is_not_counted() {
    use super::ui_tool_call_tests::{ADMIN, SERVER, fixture, invoke, post_mcp, sent};
    use crate::gateway::ui_call::{Confirm, UiCall, gate_seam};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    let fx = fixture().await;
    let principal = crate::hashing::sha256_hex(ADMIN.as_bytes())[..12].to_owned();
    let call = UiCall::new(SERVER, "write", &principal, Confirm::Confirmed);
    let cancelled = Arc::new(AtomicBool::new(false));
    let (hooked, flag) = (Arc::clone(&call), Arc::clone(&cancelled));
    let _armed = gate_seam::after_gate(move || {
        flag.store(hooked.cancel(), Ordering::SeqCst);
    });
    let before = writes_total(&fx.state.meta_mcp);
    let body = post_mcp(&fx, ADMIN, invoke("write"), Some(Arc::clone(&call))).await;
    let body: Value = serde_json::from_slice(&body).expect("json");
    assert!(
        cancelled.load(Ordering::SeqCst),
        "premise: the gate admitted the call and the deadline won: {body}"
    );
    assert!(body.get("error").is_some(), "premise: refused: {body}");
    assert_eq!(sent(&fx), 0, "premise: nothing was sent: {body}");
    assert!(
        !call.outcome().dispatched,
        "premise: not dispatched: {body}"
    );
    assert_eq!(writes_total(&fx.state.meta_mcp) - before, 0, "{body}");
}

/// R10e: a call the spend gate refuses is not counted. `k-budget` may spend
/// 1.0 a day and `read` costs 1.0, so its first `gateway_invoke` projects the
/// whole budget and is refused -32003 before hook 1, never sent. Kills hook 1
/// moved above the spend gate.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn r10e_a_call_the_spend_gate_refuses_is_not_counted() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    use std::sync::Arc;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 1.0);
    let registry = Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        Arc::clone(&registry),
    ));
    let fx = super::direct_guards_fixture::fixture_built(Answer::Ok, move |meta| {
        meta.with_cost_governance(enforcer, registry)
    })
    .await;
    let before = total(&fx);
    let (_, body) = post_meta_invoke(&fx, "k-budget", "alpha", "read", json!({}), None, None).await;
    assert_eq!(
        body["error"]["code"], -32003,
        "premise: the spend refusal: {body}"
    );
    assert_eq!(calls(&fx), 0, "premise: nothing was sent: {body}");
    assert_eq!(total(&fx) - before, 0, "{body}");
}

/// R10f: the restart GET itself is not counted. The unscoped admin's GET
/// answers 200 and the counter does not move.
#[cfg(feature = "webui")]
#[tokio::test]
async fn r10f_the_restart_get_is_not_counted() {
    use tower::ServiceExt;
    let admin = "restart-admin";
    let auth: crate::config::AuthConfig = serde_json::from_value(json!({
        "enabled": true,
        "api_keys": [{
            "key_sha256": crate::config::api_key_digest_spec(admin.as_bytes()),
            "name": admin, "admin": true, "backends": ["*"]
        }]
    }))
    .expect("auth parses");
    let (state, _store) = super::tests::audience_state(&auth, (None, None), |meta| meta).await;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/ui/api/gateway/restart")
        .header("authorization", format!("Bearer {admin}"))
        .body(axum::body::Body::empty())
        .expect("request");
    let before = writes_total(&state.meta_mcp);
    let response = super::create_router(std::sync::Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&bytes);
    assert_eq!(status.as_u16(), 200, "premise: the GET answered: {body}");
    assert_eq!(writes_total(&state.meta_mcp) - before, 0, "{body}");
}

/// A modern `/mcp` `gateway_invoke` of `alpha` `read` declaring form
/// elicitation, its params extended by `extra` (the route matrix driver's shape).
async fn modern_invoke(fx: &Fx, extra: &Value) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
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

/// R11a: a meta continuation retry (`Source::Retry`) is counted: the backend
/// runs again. The backend asks once; the retry answering it is sent and
/// moves the counter by exactly one.
#[tokio::test]
async fn r11a_a_meta_continuation_retry_is_counted() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let asked = modern_invoke(&fx, &json!({})).await;
    let state = super::direct_continuation_tests::state_of(&asked);
    assert_eq!(calls(&fx), 1, "premise: the opening call was sent: {asked}");
    let before = total(&fx);
    let retry = json!({
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "acct-1"}}},
    });
    let answer = modern_invoke(&fx, &retry).await;
    assert!(answer.get("error").is_none(), "premise: answered: {answer}");
    assert_eq!(calls(&fx), 2, "premise: the retry was sent: {answer}");
    assert_eq!(total(&fx) - before, 1, "{answer}");
}

/// Accepts every question a bridged round asks, counting them.
#[derive(Default)]
struct Accepting {
    asked: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::ClientChannel for Accepting {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, crate::gateway::input_bridge::DeliveryError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Ok(
            json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {"account": "work"}}}),
        )
    }
}

/// R11b: a bridged input round is counted once with its call. The backend
/// asks once, the gateway bridges the question to the client and re-sends
/// the answered call inside the same invoke: the backend runs twice, the
/// counter moves by exactly one (the round adds nothing).
#[tokio::test]
async fn r11b_a_bridged_round_adds_nothing_to_its_call() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let channel = Accepting::default();
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({
            "_meta": {
                crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
                crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
            }
        })),
        None,
    )
    .declared_capabilities();
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("k-std"),
        authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
        era: crate::protocol::meta::Era::Legacy,
        input_capabilities: declared,
        channel: &channel,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let before = total(&fx);
    let answer = fx
        .state
        .meta_mcp
        .invoke_tool_for_test(
            &json!({"server": "alpha", "tool": "read", "arguments": {}}),
            Some("session-r11b"),
            &ctx,
        )
        .await
        .expect("the opening call and the bridged round succeed");
    assert_eq!(
        channel.asked.load(Ordering::SeqCst),
        1,
        "premise: one question: {answer}"
    );
    assert_eq!(
        calls(&fx),
        2,
        "premise: opening call plus bridged round: {answer}"
    );
    assert_eq!(total(&fx) - before, 1, "{answer}");
}

/// R11c: a transport-level resend of one dispatch is counted once. The
/// `idempotentHint` `echo` answers 503 on every attempt, so the backend's
/// retry loop resends it (the secret-echo T1.22 harness): the backend sees at
/// least two attempts and the counter moves by exactly one.
#[tokio::test]
async fn r11c_a_transport_resend_counts_once() {
    use super::secret_echo_tests::{Calls, Reply, echo_server};
    use std::sync::Arc;
    use tower::ServiceExt;
    let calls = Calls::default();
    let url = echo_server(Arc::clone(&calls), Reply::RetryableRefusal).await;
    let backend = Arc::new(crate::backend::Backend::new(
        "echoes",
        crate::config::BackendConfig {
            enabled: true,
            transport: crate::config::TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            ..crate::config::BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(30),
    ));
    let (state, _store) = super::tests::test_router_app_state_with_backend(backend).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "gateway_invoke",
                "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}}
            }})
            .to_string(),
        ))
        .expect("request");
    let before = writes_total(&state.meta_mcp);
    let response = super::create_router(Arc::clone(&state))
        .oneshot(request)
        .await
        .expect("response");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&bytes);
    let attempts = calls.lock().len();
    assert!(
        attempts >= 2,
        "premise: resent ({attempts} attempts): {body}"
    );
    assert_eq!(writes_total(&state.meta_mcp) - before, 1, "{body}");
}

/// R12a: a call the backend answers with an error is still counted: hook 1
/// runs before the send. `gateway_invoke` of `read` on a backend answering a
/// JSON-RPC error moves the counter by one.
#[tokio::test]
async fn r12a_a_backend_error_is_still_counted() {
    let fx = fixture(Answer::RpcError(-32001), |_| {}).await;
    let before = total(&fx);
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", json!({}), None, None).await;
    assert!(
        body.get("error").is_some() || body["result"]["isError"] == true,
        "premise: the backend's error reached the client: {body}"
    );
    assert_eq!(calls(&fx), 1, "premise: the call was sent: {body}");
    assert_eq!(total(&fx) - before, 1, "{body}");
}
