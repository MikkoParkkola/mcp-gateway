// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8429 end to end: a playbook step on a REST capability account whose
//! custody is busy before anything is sent ends the plan with the shared
//! retryable error. Two Busy routes, both pre-send: the caller view (the
//! step's `invoke_tool` answers `Err`) and the in-backend lease recheck (the
//! dispatch error is folded into an `isError` result today). A vendor error
//! after the send keeps today's step semantics.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::AuthConfig;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    CAPABILITY_SERVER, CAPABILITY_TOOL, CapabilityAccount,
};

struct Harness {
    router: axum::Router,
    account: CapabilityAccount,
    _store: crate::gateway::router::tests::FixtureDir,
}

/// A gateway serving the capability account, with playbook `pb` of `steps`
/// capability calls under `on_error`.
async fn harness(account: CapabilityAccount, on_error: &str, steps: usize) -> Harness {
    let steps: Vec<Value> = (0..steps)
        .map(|i| {
            json!({"name": format!("s{i}"), "server": CAPABILITY_SERVER,
                "tool": CAPABILITY_TOOL, "arguments": {}})
        })
        .collect();
    let definition = serde_json::from_value(json!({
        "playbook": "1.0", "name": "pb", "description": "capability steps",
        "steps": steps, "on_error": on_error, "max_retries": 3
    }))
    .expect("the playbook deserialises");
    let (state, store) = super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| {
            let mut meta = account.install(meta);
            // Production builds the gateway with an idempotency cache; the
            // keyed rows need it to scope and replay each step's key.
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(300),
            );
            let mut engine = crate::playbook::PlaybookEngine::new();
            engine.register(definition);
            meta.set_playbook_engine(engine);
            meta
        },
    )
    .await;
    Harness {
        router: super::create_router(Arc::clone(&state)),
        account,
        _store: store,
    }
}

/// POST `tools/call name` as alice, whose verified identity rides in as a
/// request extension.
async fn call(harness: &Harness, name: &str, arguments: Value) -> Value {
    call_keyed(harness, name, arguments, None).await
}

/// [`call`], under idempotency `key` when given.
async fn call_keyed(harness: &Harness, name: &str, arguments: Value, key: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    if let Some(key) = key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    }
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": meta}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(CapabilityAccount::alice());
    let response = harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn run_playbook(harness: &Harness) -> Value {
    call(harness, "gateway_run_playbook", json!({"name": "pb"})).await
}

fn assert_retryable(reply: &Value, row: &str) {
    assert_eq!(
        reply.pointer("/error/code"),
        Some(&json!(-32603)),
        "{row}: not the shared transient error: {reply}"
    );
    assert_eq!(
        reply.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "{row}: not retryable: {reply}"
    );
}

/// STEP.1, in-backend recheck: the mint's release passes and the recheck in
/// `CapabilityBackend` meets `Busy`, before any send. Under `abort` the plan
/// must stop with the retryable error. Red on the line: the folded `isError`
/// value is recorded as a completed step and the plan answers a result.
#[tokio::test]
async fn a_recheck_busy_step_ends_an_abort_plan_retryable() {
    let harness = harness(CapabilityAccount::start(false).await, "abort", 1).await;
    harness.account.fail_releases_after_for_test(1);
    let reply = run_playbook(&harness).await;
    assert_eq!(
        harness.account.peer_requests(),
        0,
        "premise: nothing reached the vendor: {reply}"
    );
    assert_retryable(&reply, "STEP.1 recheck");
}

/// Exclusion control (P1a): a direct `gateway_invoke` meeting the same
/// in-backend recheck Busy keeps today's answer, a folded `isError` result
/// carrying the transient text. The playbook-only fold-point change must not
/// reach it.
#[tokio::test]
async fn a_direct_invoke_recheck_busy_keeps_its_folded_answer() {
    let harness = harness(CapabilityAccount::start(false).await, "abort", 1).await;
    harness.account.fail_releases_after_for_test(1);
    let reply = call(
        &harness,
        "gateway_invoke",
        json!({"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}}),
    )
    .await;
    assert_eq!(harness.account.peer_requests(), 0, "premise: {reply}");
    assert_eq!(
        reply.pointer("/result/isError"),
        Some(&json!(true)),
        "control: the direct answer's shape changed: {reply}"
    );
    assert!(
        reply.to_string().contains("temporarily unavailable, retry"),
        "control: {reply}"
    );
}

/// STEP.1, caller view: custody unreadable, so the step's call is refused
/// with the sealed retryable error before its backend. Under `continue` the
/// plan must stop there, and its successor must not start: the successor's
/// own custody lookups are the evidence. Red on the line: `s0` is null-filled
/// and `s1` runs.
#[tokio::test]
async fn a_view_busy_step_ends_a_continue_plan_before_its_successor() {
    let harness = harness(CapabilityAccount::start(false).await, "continue", 2).await;
    harness.account.fail_custody_for_test(true);
    let before = harness.account.resolves();
    let single = call(
        &harness,
        "gateway_invoke",
        json!({"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}}),
    )
    .await;
    assert_retryable(&single, "premise: a lone busy call");
    let per_call = harness.account.resolves() - before;
    let before = harness.account.resolves();
    let reply = run_playbook(&harness).await;
    assert_retryable(&reply, "STEP.1 view");
    assert_eq!(
        harness.account.resolves() - before,
        per_call,
        "STEP.1 view: a successor step started (custody lookups past one step's): {reply}"
    );
    assert_eq!(harness.account.peer_requests(), 0, "{reply}");
}

/// PBERR.1 end to end: the vendor answers 400, a tool error past the send.
/// Under `continue` the step is failed and null-filled with its reason, and
/// the successor runs and is served. Red on the line: `s0` is recorded
/// completed with the error value as its result.
#[tokio::test]
async fn a_vendor_error_step_is_a_failed_step() {
    let harness = harness(
        CapabilityAccount::start_answering(&[400]).await,
        "continue",
        2,
    )
    .await;
    let reply = run_playbook(&harness).await;
    assert!(reply.get("error").is_none(), "PBERR.1: {reply}");
    assert_eq!(
        harness.account.peer_requests(),
        2,
        "PBERR.1: both steps reached the vendor: {reply}"
    );
    let result = plan_result(&reply);
    assert_eq!(result["steps_failed"], json!(["s0"]), "PBERR.1: {reply}");
    assert_eq!(result["steps_completed"], json!(["s1"]), "PBERR.1: {reply}");
    assert_eq!(
        result.pointer("/output/s0"),
        Some(&Value::Null),
        "PBERR.1: {reply}"
    );
}

/// D3 end to end: under `abort` a vendor tool error ends the plan with the
/// fixed message, and the tool's text reaches the caller only as the error's
/// `data.tool_text`, capped. Red before the renderer forwarded the key: the
/// answer's `data` was absent, so the caller lost the reason.
#[tokio::test]
async fn an_aborted_tool_error_answer_carries_the_capped_tool_text() {
    let harness = harness(CapabilityAccount::start_answering(&[400]).await, "abort", 2).await;
    let reply = run_playbook(&harness).await;
    let message = reply
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("D3: the abort is not an error: {reply}"));
    assert!(
        message.contains("the tool reported an error"),
        "D3: not the fixed message: {reply}"
    );
    let text = reply
        .pointer("/error/data/tool_text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("D3: the caller lost the tool's text: {reply}"));
    assert!(
        !text.is_empty() && text.chars().count() <= 257 && !message.contains(text),
        "D3: the tool's text is empty, uncapped, or in the message: {reply}"
    );
}

/// STEP.1 partial run, keyed: `s0` is served, then `s1`'s in-backend
/// recheck meets Busy. The plan ends there, and its answer must not read as
/// retryable or unsent, because `s0` reached the vendor. The same key sent
/// again after recovery does not send `s0` a second time. Red on the line:
/// the plan answers a result with `s1` recorded completed.
#[tokio::test]
async fn a_busy_step_after_a_served_one_ends_the_plan_without_a_retry_label() {
    // One served call's custody releases, measured on a gateway of its own so
    // its response cache cannot serve the plan's `s0`.
    let per_call = {
        let probe = harness(CapabilityAccount::start(false).await, "continue", 1).await;
        let served = call(
            &probe,
            "gateway_invoke",
            json!({"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}}),
        )
        .await;
        assert!(
            served.get("error").is_none(),
            "premise: a served call: {served}"
        );
        probe.account.releases()
    };
    let harness = harness(CapabilityAccount::start(false).await, "continue", 2).await;
    let sent = harness.account.peer_requests();
    // `s0` passes all its releases and `s1` its mint's; `s1`'s first recheck,
    // in the backend, meets Busy before its send.
    harness.account.fail_releases_after_for_test(per_call + 1);
    let reply = call_keyed(
        &harness,
        "gateway_run_playbook",
        json!({"name": "pb"}),
        Some("pb-8429"),
    )
    .await;
    assert_eq!(
        harness.account.peer_requests(),
        sent + 1,
        "premise: s0 reached the vendor and s1 did not: {reply}"
    );
    assert!(
        reply.get("error").is_some(),
        "STEP.1 partial: the plan carried on past a busy step: {reply}"
    );
    assert!(
        reply.pointer("/error/data/retryable").is_none(),
        "STEP.1 partial: labelled retryable after s0 was sent: {reply}"
    );
    harness.account.fail_custody_for_test(false);
    let again = call_keyed(
        &harness,
        "gateway_run_playbook",
        json!({"name": "pb"}),
        Some("pb-8429"),
    )
    .await;
    assert_eq!(
        harness.account.peer_requests(),
        sent + 1,
        "STEP.1 partial: the same key sent s0 again: {again}"
    );
    assert_eq!(
        again.get("error"),
        reply.get("error"),
        "STEP.1 partial: the same key does not replay the plan's answer: {again}"
    );
}

/// D1 under `retry`: the vendor answers 500 to every request, which the
/// gateway answers as a tool error. The vendor may have acted, so the step is
/// sent once, keyed or not, and recorded failed. Red before the hold fix
/// (unkeyed): the vendor saw 3 requests.
#[tokio::test]
async fn a_tool_error_step_is_sent_once_under_retry_keyed_or_not() {
    for (key, sends) in [(None, 1), (Some("pb-8429-retry"), 1)] {
        let harness = harness(
            CapabilityAccount::start_answering(&[500, 500, 500, 500]).await,
            "retry",
            1,
        )
        .await;
        let reply = call_keyed(&harness, "gateway_run_playbook", json!({"name": "pb"}), key).await;
        assert_eq!(
            harness.account.peer_requests(),
            sends,
            "D1 retry key={key:?}: vendor requests: {reply}"
        );
        let result = plan_result(&reply);
        assert_eq!(
            result["steps_failed"],
            json!(["s0"]),
            "key={key:?}: {reply}"
        );
    }
}

/// The `PlaybookResult` a successful `gateway_run_playbook` answer carries
/// as its text content.
fn plan_result(reply: &Value) -> Value {
    reply
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_else(|| panic!("not a playbook result: {reply}"))
}
