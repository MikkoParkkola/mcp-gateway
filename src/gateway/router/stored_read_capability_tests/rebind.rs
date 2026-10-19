// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8407 REC.2-4 on the live path: a capability's `auth.account` is
//! hot-re-bound from `WORK` (revoked) to `PERSONAL` (live), which its reload
//! allows. A stored result produced under `WORK` is not served afterwards,
//! on the sync retry (single call and plan) or on a task read, and nothing
//! reaches the peer again. The control keeps the binding: served.

use super::*;

/// The router over `account` (cache armed, as production arms it) and the
/// served Meta-MCP, which a re-bind registers the capability on.
async fn served(
    account: &CapabilityAccount,
) -> (
    axum::Router,
    Arc<crate::gateway::meta_mcp::MetaMcp>,
    impl Sized,
) {
    let (state, store) = super::super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| {
            let mut meta = account.install(meta);
            meta.enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                std::time::Duration::from_secs(60),
            );
            meta
        },
    )
    .await;
    let meta = Arc::clone(&state.meta_mcp);
    (super::super::create_router(Arc::clone(&state)), meta, (state, store))
}

fn single() -> Value {
    json!({"name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}}})
}

fn plan() -> Value {
    json!({"name": "gateway_execute",
        "arguments": {"tool": format!("{CAPABILITY_SERVER}:{CAPABILITY_TOOL}"), "arguments": {}}})
}

/// The first run: it succeeds and reaches the peer once.
async fn first_run(router: &axum::Router, account: &CapabilityAccount, name: &str, params: Value) {
    let first = send(router, "tools/call", name, params).await;
    assert!(
        first.get("error").is_none() && first.pointer("/result/isError") != Some(&json!(true)),
        "premise: the call succeeded: {first}"
    );
    assert_eq!(account.peer_requests(), 1, "premise: one send: {first}");
}

/// RB-cap-sync (REC.4; mutant M-rec-sync): the keyed sync retry of a single
/// call and of a plan after the re-bind is refused, nothing sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_cap_sync_retained_result_is_refused_after_a_capability_rebind() {
    for (row, name, params) in [
        ("RB-cap-sync single", "gateway_invoke", single()),
        ("RB-cap-sync plan", "gateway_execute", plan()),
    ] {
        let account = CapabilityAccount::start_two_accounts().await;
        let (router, meta, _keep) = served(&account).await;
        let params = keyed(params, row);
        first_run(&router, &account, name, params.clone()).await;
        account.revoke().await;
        account.rebind_to_personal(&meta);
        let again = send(&router, "tools/call", name, params).await;
        eprintln!("{row}: {again}");
        assert!(
            again.get("error").is_some() && again.get("result").is_none(),
            "{row}: the stored result went out: {again}"
        );
        assert_eq!(account.peer_requests(), 1, "{row}: sent again: {again}");
    }
}

/// RB-cap-task (REC.2, REC.3; mutant M-rec-read): the task read after the
/// re-bind is refused; nothing is sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_cap_task_read_is_refused_after_a_capability_rebind() {
    let account = CapabilityAccount::start_two_accounts().await;
    let (router, meta, _keep) = served(&account).await;
    let mut params = keyed(single(), "rb-cap-task");
    params["task"] = json!({});
    let made = send(&router, "tools/call", "gateway_invoke", params).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let done = loop {
        let got = task_get(&router, &id).await;
        if got.pointer("/result/status") == Some(&json!("completed")) {
            break got;
        }
        assert!(std::time::Instant::now() < bound, "premise: completes: {got}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(done.get("error").is_none(), "premise: delivered: {done}");
    account.revoke().await;
    account.rebind_to_personal(&meta);
    let read = task_get(&router, &id).await;
    eprintln!("RB-cap-task: {read}");
    assert!(read.get("error").is_some(), "RB-cap-task: served: {read}");
    assert_eq!(account.peer_requests(), 1, "RB-cap-task: sent again");
}

/// RB-cap-ctl (REC.3 control): two accounts installed, no re-bind, `WORK`
/// live: the replay is served, nothing sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rb_cap_ctl_without_a_rebind_the_replay_is_served() {
    let account = CapabilityAccount::start_two_accounts().await;
    let (router, _meta, _keep) = served(&account).await;
    let params = keyed(single(), "rb-cap-ctl");
    first_run(&router, &account, "gateway_invoke", params.clone()).await;
    let again = send(&router, "tools/call", "gateway_invoke", params).await;
    assert!(again.get("error").is_none(), "RB-cap-ctl: {again}");
    assert_eq!(account.peer_requests(), 1, "RB-cap-ctl: sent again");
}
