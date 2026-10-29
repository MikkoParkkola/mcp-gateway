// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 P4: stdio's route stage (`stdio_dispatch.rs`) serves no retained
//! plan result to an operator whose grant was revoked (test plan t0). The
//! HTTP rows are in `gateway/router/plan_replay_liveness_tests.rs`.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::AuthConfig;
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::server::account_bindings::ServeMode;

const MARKER: &str = "stored-plan-output-8406-stdio";
const PLAYBOOK: &str = "two_reads";

fn two_reads() -> crate::playbook::PlaybookDefinition {
    let read = |name: &str| json!({"name": name, "server": BACKEND, "tool": "read", "arguments": {"folder": "inbox"}});
    serde_json::from_value(json!({"playbook": "1.0", "name": PLAYBOOK,
        "description": "reads", "steps": [read("s0"), read("s1")]}))
    .expect("the playbook deserialises")
}

fn keyed_playbook(key: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {
    "name": "gateway_run_playbook",
    "arguments": {"name": PLAYBOOK, "arguments": {}},
    "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
    }}})
}

/// P4 (stdio twin of P1): a keyed `gateway_run_playbook` runs while
/// connected; the grant is revoked; the same call is refused and nothing is
/// sent. Red on the release line: the retained result is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p4_stdio_keyed_playbook_replay_after_revocation_is_refused() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = gateway.take_meta();
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(two_reads());
    meta.set_playbook_engine(engine);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    if let Some(backend) = gateway.backends().get(BACKEND) {
        backend.store_shared_tools_for_test(vec![tool]);
    }
    let meta = Arc::new(meta);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let session = super::super::STDIO_SESSION_ID;
    for _ in 0..2 {
        gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let first = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4"), session)
        .await
        .expect("a response");
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    let sent = gateway.tool_calls().len();
    let entered = crate::gateway::meta_mcp::plan_entries::count(&meta);
    gateway.revoke_operator_grant().await;
    let again = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4"), session)
        .await
        .expect("a response");
    assert!(
        !again.to_string().contains(MARKER),
        "P4: the stored plan output was served after revocation: {again}"
    );
    assert!(again.get("error").is_some(), "P4: not a refusal: {again}");
    assert_eq!(
        gateway.tool_calls().len(),
        sent,
        "P4: the replay reached the backend: {again}"
    );
    // mProceed is killed only by this entries assert: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    assert_eq!(
        crate::gateway::meta_mcp::plan_entries::count(&meta),
        entered,
        "P4: the replay entered the plan executor: {again}"
    );
}

/// P4u (stdio, RED at 1577d7ff6; kills mSyncStdio and mStdioRender): a
/// keyed playbook runs; custody then fails (the account `Unavailable`); the
/// same call is answered exactly as the live twin (a fresh key) answers,
/// `error.data` kept (measured: -32603 with `{"retryable": true}`), with
/// nothing sent and no plan executor entered. Rendering the refusal through
/// `JsonRpcResponse::error` (mStdioRender) drops the data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p4u_stdio_unavailable_replay_answers_the_live_twin_with_its_data() {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let meta = gateway.take_meta();
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(two_reads());
    meta.set_playbook_engine(engine);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    if let Some(backend) = gateway.backends().get(BACKEND) {
        backend.store_shared_tools_for_test(vec![tool]);
    }
    let meta = Arc::new(meta);
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let session = super::super::STDIO_SESSION_ID;
    for _ in 0..2 {
        gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let first = Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4u"), session)
        .await
        .expect("a response");
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    let sent = gateway.tool_calls().len();
    let entered = crate::gateway::meta_mcp::plan_entries::count(&meta);
    gateway.fail_custody_for_test(true);
    let mut again =
        Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4u"), session)
            .await
            .expect("a response");
    let replay_sends = gateway.tool_calls().len() - sent;
    // mProceed is killed only by this entries count: a fall-through to the
    // live run refuses the same way and sends nothing. Keep it.
    let replay_entries = crate::gateway::meta_mcp::plan_entries::count(&meta) - entered;
    let mut live =
        Gateway::dispatch_single(&meta, &policy, &mtls, &keyed_playbook("p4u-live"), session)
            .await
            .expect("a response");
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the live twin is the outage error: {live}"
    );
    assert_eq!(
        live.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "premise: the live twin carries its data: {live}"
    );
    assert!(
        !again.to_string().contains(MARKER),
        "P4u: the stored plan output was served: {again}"
    );
    again["id"] = Value::Null;
    live["id"] = Value::Null;
    assert_eq!(again, live, "P4u: the replay is not the live twin's answer");
    assert_eq!(replay_sends, 0, "P4u: the replay reached the backend");
    assert_eq!(
        replay_entries, 0,
        "P4u: the replay entered the plan executor"
    );
}

const REPLAY: &str = "Nonce replay detected";

/// A stdio gateway over the connected managed account, signing every
/// `tools/call` with a required nonce in `_meta` (MIK-8406 G2), and the
/// playbook engine armed.
struct Signed {
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    policy: Arc<crate::security::ToolPolicy>,
    mtls: Arc<crate::mtls::MtlsPolicy>,
    /// Last: it owns the Meta-MCP's audit log, which must outlive every
    /// field above that holds the logger.
    gateway: DirectAccountGateway,
}

fn signed() -> Signed {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), &Binding::Connected);
    let mut meta = gateway.take_meta();
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(two_reads());
    meta.set_playbook_engine(engine);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"plan-replay-stdio-signing-secret-32-bytes".to_vec(),
            None,
            "plan-replay-stdio".into(),
        ),
        std::time::Duration::from_secs(300),
        true,
    );
    meta.set_signing_scope(crate::gateway::meta_mcp::signing::SigningScope::EveryToolCall);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    if let Some(backend) = gateway.backends().get(BACKEND) {
        backend.store_shared_tools_for_test(vec![tool]);
    }
    Signed {
        gateway,
        meta: Arc::new(meta),
        policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls: Arc::new(crate::mtls::MtlsPolicy::from_config(
            &crate::mtls::MtlsConfig::default(),
        )),
    }
}

/// The keyed playbook call signed under `nonce`, sent over stdio.
async fn signed_send(fx: &Signed, key: &str, nonce: &str) -> Value {
    let mut request = keyed_playbook(key);
    request["params"]["_meta"][crate::gateway::meta_mcp::signing::NONCE_META] = json!(nonce);
    let session = super::super::STDIO_SESSION_ID;
    Gateway::dispatch_single(&fx.meta, &fx.policy, &fx.mtls, &request, session)
        .await
        .expect("a response")
}

/// The error message of `answer`, or "" when it is not an error.
fn error_message(answer: &Value) -> &str {
    answer
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// P10 (stdio; MIK-8406, mutant mRefund): a signed keyed playbook runs under
/// `n1`; the grant is revoked; its replay under `n2` is refused with the
/// account's resolution error, and `n2` stays spent: a fresh-key call
/// re-using it is refused as a replay, while a fresh nonce reaches the live
/// refusal (control). A plan refusal that asked for the refund (mRefund)
/// would give `n2` back. On HTTP a signed plan needs the hardened posture,
/// which refuses the sole operator (no per-caller identity), so the signed
/// rows run on stdio's route stage, which takes the same exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p10_stdio_a_refused_plan_replay_keeps_its_nonce_spent() {
    let fx = signed();
    for _ in 0..2 {
        fx.gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let first = signed_send(&fx, "p10", "p10-n1").await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    fx.gateway.revoke_operator_grant().await;
    let refused = signed_send(&fx, "p10", "p10-n2").await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32603)),
        "premise: the replay is refused with the resolution error: {refused}"
    );
    let second_use = signed_send(&fx, "p10-reuse", "p10-n2").await;
    assert!(
        error_message(&second_use).contains(REPLAY),
        "P10: the refused replay's nonce was given back: {second_use}"
    );
    let fresh = signed_send(&fx, "p10-fresh", "p10-n3").await;
    assert!(
        fresh.get("error").is_some() && !error_message(&fresh).contains(REPLAY),
        "control: a fresh nonce reaches the live refusal: {fresh}"
    );
}

/// PG2-stdio (MIK-8406 G2, mutant mNoSettle): a signed keyed playbook runs
/// under `n1`; custody then fails, so its replay under `n2` is refused
/// retryable before any effect, and the refusal gives `n2` back. Once custody
/// recovers, the same replay under `n2` is served the stored output; `n2` is
/// then spent, and a third send under it is a replay. A refusal exit that
/// never settled (mNoSettle) keeps `n2` spent, so the recovered retry is
/// refused as a replay. Nothing is sent after the first run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg2_stdio_a_busy_plan_refusal_gives_its_nonce_back_once() {
    let fx = signed();
    for _ in 0..2 {
        fx.gateway
            .answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));
    }
    let first = signed_send(&fx, "pg2", "pg2-n1").await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: the plan ran: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.fail_custody_for_test(true);
    let busy = signed_send(&fx, "pg2", "pg2-n2").await;
    assert_eq!(
        busy.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "premise: the replay is refused retryable while custody fails: {busy}"
    );
    fx.gateway.fail_custody_for_test(false);
    let served = signed_send(&fx, "pg2", "pg2-n2").await;
    assert!(
        served.to_string().contains(MARKER),
        "PG2-stdio: the recovered retry was not served (nonce kept spent?): {served}"
    );
    let third = signed_send(&fx, "pg2", "pg2-n2").await;
    assert!(
        error_message(&third).contains(REPLAY),
        "PG2-stdio: the nonce was given back twice: {third}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "PG2-stdio: a replay reached the backend"
    );
}
