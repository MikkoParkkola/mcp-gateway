// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8475 (CAPCD.1-4): a capability tool that dispatches under a personal
//! account (`auth.account`) and is in error-rate cooldown. A caller whose
//! grant was revoked must be answered as for a missing name, live and on a
//! stored read; a caller with a view keeps the cooldown answer. Driven
//! through `/mcp` as alice, on the parent's fixture.

use super::*;

/// A router over `account`'s capability, with its application state kept so
/// the cooldown can be armed.
async fn router_and_state(
    account: &CapabilityAccount,
) -> (axum::Router, Arc<super::super::AppState>, impl Sized) {
    let (state, store) = super::super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| account.install(meta),
    )
    .await;
    (
        super::super::create_router(Arc::clone(&state)),
        state,
        store,
    )
}

/// Push the capability tool into error-rate cooldown.
fn cool(state: &super::super::AppState) {
    let kill_switch = state.meta_mcp.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(CAPABILITY_SERVER, CAPABILITY_TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(CAPABILITY_SERVER, CAPABILITY_TOOL),
        "premise: {CAPABILITY_TOOL} is in cooldown"
    );
}

/// A live `gateway_invoke` of the capability tool (`tool` names it).
async fn invoke(router: &axum::Router, tool: &str) -> Value {
    send(
        router,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": CAPABILITY_SERVER, "tool": tool, "arguments": {}},
            "_meta": modern_meta()}),
    )
    .await
}

/// `answer` with only the caller's own input normalised: the `id`, and the
/// tool name it asked for.
fn normalised(answer: &Value, sent: &str) -> Value {
    let mut out: Value =
        serde_json::from_str(&answer.to_string().replace(sent, "<REQUESTED>")).expect("JSON");
    out["id"] = Value::Null;
    out
}

/// CAPCD.1 (live): a revoked caller invoking a cooling capability tool is
/// answered as before the cooldown (the account step first).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_caller_invoking_a_cooling_capability_answers_as_before_the_cooldown() {
    let account = CapabilityAccount::start(false).await;
    let (router, state, _keep) = router_and_state(&account).await;
    account.revoke().await;
    // The live call answers its own caller's revoked account specifically
    // (the caller named the account), so the twin is the same call before
    // the cooldown, not a missing name.
    let before = invoke(&router, CAPABILITY_TOOL).await;
    eprintln!("MIK-8475 live revoked, not cooling: {before}");
    cool(&state);
    let sent = account.peer_requests();
    let live = invoke(&router, CAPABILITY_TOOL).await;
    eprintln!("MIK-8475 live revoked+cooling: {live}");
    assert_eq!(
        normalised(&live, CAPABILITY_TOOL),
        normalised(&before, CAPABILITY_TOOL),
        "MIK-8475: the cooldown changed a revoked caller's live answer"
    );
    assert_eq!(account.peer_requests(), sent, "MIK-8475: a live call sent");
}

/// CAPCD.2 (stored): a revoked caller reading a stored task of a cooling
/// capability tool is answered as before the cooldown (-32601, T11).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_caller_reading_a_cooling_capability_task_answers_as_absent() {
    let account = CapabilityAccount::start(false).await;
    let (router, state, _keep) = router_and_state(&account).await;
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("8475-stored");
    let made = send(
        &router,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while task_get(&router, &id).await.pointer("/result/status") != Some(&json!("completed")) {
        assert!(std::time::Instant::now() < bound, "premise: completes");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    account.revoke().await;
    let before = task_get(&router, &id).await;
    assert_eq!(
        before.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise (T11): {before}"
    );
    cool(&state);
    let sent = account.peer_requests();
    let read = task_get(&router, &id).await;
    eprintln!("MIK-8475 stored revoked+cooling: {read}");
    assert_eq!(
        normalised(&read, CAPABILITY_TOOL),
        normalised(&before, CAPABILITY_TOOL),
        "MIK-8475: the cooling read differs from the read before the cooldown"
    );
    assert_eq!(
        account.peer_requests(),
        sent,
        "MIK-8475: a stored read sent"
    );
}

/// CAPCD.3 (control): a caller WITH a view and a cooling tool still gets the
/// cooldown refusal on a live call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_with_a_view_invoking_a_cooling_capability_still_meets_the_cooldown() {
    let account = CapabilityAccount::start(false).await;
    let (router, state, _keep) = router_and_state(&account).await;
    cool(&state);
    let sent = account.peer_requests();
    let live = invoke(&router, CAPABILITY_TOOL).await;
    eprintln!("MIK-8475 live with view+cooling: {live}");
    assert!(
        live.get("error").is_some(),
        "MIK-8475 control: refused: {live}"
    );
    assert!(
        live.to_string().contains("temporarily disabled"),
        "MIK-8475 control: the cooldown answer: {live}"
    );
    assert_eq!(account.peer_requests(), sent, "MIK-8475 control: sent");
}
