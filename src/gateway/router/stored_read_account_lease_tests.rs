// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.1 account-outcome rows on the managed-account backend
//! (s1-t0 U1, C6): a custody read that fails proves nothing about the
//! grant, so a stored read answers retryable, never -32601, and serves once
//! custody recovers. Driven through `/mcp` as the sole operator.

use serde_json::{Value, json};

use super::{BACKEND, Fx, MARKER, TOOL, fixture, modern_meta, send, task_get};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::DirectAccountGateway;

/// A finished task of the operator's `read`, its output served once.
async fn finished(fx: &Fx, key: &str) -> String {
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let made = send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(fx, &id).await;
        if got.to_string().contains(MARKER) {
            return id;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: served once: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn assert_retryable(read: &Value, row: &str) {
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32603)),
        "{row}: {read}"
    );
    assert_eq!(
        read.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "{row}: retryable: {read}"
    );
    assert!(!read.to_string().contains(MARKER), "{row}: output: {read}");
}

/// U1: custody fails on a warm read: retryable (M21, Unavailable read as
/// NoView, answers -32601); once custody recovers, the same read serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u1_a_failing_custody_read_answers_retryable_then_serves() {
    let fx = fixture().await;
    let id = finished(&fx, "s1-u1").await;
    fx.gateway.fail_custody_for_test(true);
    assert_retryable(&task_get(&fx, &id).await, "U1");
    fx.gateway.fail_custody_for_test(false);
    let read = task_get(&fx, &id).await;
    assert!(
        read.to_string().contains(MARKER),
        "U1: served after recovery: {read}"
    );
}

/// C6: the same on a cold view (the operator's slot evicted): retryable,
/// never -32601, and no cold attempt is claimed while the account is not
/// proven; after recovery one read resolves and serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c6_a_cold_read_under_failing_custody_answers_retryable() {
    let fx = fixture().await;
    let id = finished(&fx, "s1-c6").await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let binding = DirectAccountGateway::operator_binding();
    backend.age_per_user_slot_for_test(&binding, 400);
    backend.evict_idle_per_user_entries(std::time::Duration::from_secs(300));
    fx.gateway.fail_custody_for_test(true);
    let releases = fx.gateway.releases();
    assert_retryable(&task_get(&fx, &id).await, "C6");
    assert_eq!(fx.gateway.releases(), releases, "C6: nothing resolved");
    fx.gateway.fail_custody_for_test(false);
    fx.gateway.rearm_operator_slot_for_test();
    let read = task_get(&fx, &id).await;
    assert!(
        read.to_string().contains(MARKER),
        "C6: served after recovery: {read}"
    );
}

/// Record the operator's NoView index entry the way production does: a
/// listing after the grant is gone.
async fn list_tools(fx: &Fx) {
    let _ = send(
        fx,
        "tools/list",
        "tools/list",
        json!({"_meta": modern_meta()}),
    )
    .await;
}

fn assert_absent(read: &Value, row: &str) {
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "{row}: {read}"
    );
    assert!(!read.to_string().contains(MARKER), "{row}: output: {read}");
}

/// L4: a NoView entry while the account is NoView: -32601, and no cold
/// attempt (one custody read, the pre-pass's own; M20 claims anyway).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l4_a_no_view_entry_with_a_revoked_account_stays_absent() {
    let fx = fixture().await;
    let id = finished(&fx, "s1-l4").await;
    fx.gateway.revoke_operator_grant().await;
    list_tools(&fx).await;
    let reads = fx.gateway.resolves();
    assert_absent(&task_get(&fx, &id).await, "L4");
    assert_eq!(
        fx.gateway.resolves() - reads,
        1,
        "L4: the pre-pass read only"
    );
}

/// L4b: no index entry and a NoView account: -32601 and no claim (M42).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l4b_no_entry_with_a_revoked_account_claims_nothing() {
    let fx = fixture().await;
    let id = finished(&fx, "s1-l4b").await;
    fx.gateway.revoke_operator_grant().await;
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .forget_caller_slots_for_test();
    let reads = fx.gateway.resolves();
    assert_absent(&task_get(&fx, &id).await, "L4b");
    assert_eq!(
        fx.gateway.resolves() - reads,
        1,
        "L4b: the pre-pass read only"
    );
}

/// L5: a NoView entry, then the grant is reconnected (account Live): the
/// read claims, resolves once and serves (M43: NoView never claimable).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l5_a_reconnected_grant_reclaims_a_no_view_entry() {
    let fx = fixture().await;
    let id = finished(&fx, "s1-l5").await;
    fx.gateway.revoke_operator_grant().await;
    list_tools(&fx).await;
    fx.gateway.reconnect_operator_grant_for_test().await;
    // The reconnected grant selects a new slot: the binding the vault now
    // gives, read without a mint.
    let binding = fx
        .state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the reconnected grant has a view");
    fx.gateway.rearm_operator_slot_at_for_test(&binding);
    let releases = fx.gateway.releases();
    let read = task_get(&fx, &id).await;
    assert!(read.to_string().contains(MARKER), "L5: served: {read}");
    assert_eq!(fx.gateway.releases() - releases, 1, "L5: one resolution");
}

/// L2: after a grant rotation, warm read A sees its indexed slot no longer
/// matches the grant and is parked before its forget; read B forgets, claims
/// and is held as winner. A's forget then finds B's lease, not the entry it
/// saw, and leaves it: A answers retryable, B serves, one resolver in all
/// (M18: an unconditional forget lets A claim too).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l2_a_stale_warm_forget_leaves_a_newer_lease() {
    let fx = std::sync::Arc::new(fixture().await);
    let id = finished(&fx, "s1-l2").await;
    fx.gateway.rotate_operator_grant().await;
    let binding = fx
        .state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the rotated grant has a view");
    fx.gateway.rearm_operator_slot_at_for_test(&binding);
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let releases = fx.gateway.releases();
    let read = |fx: &std::sync::Arc<Fx>| {
        let (fx, id) = (std::sync::Arc::clone(fx), id.clone());
        tokio::spawn(async move { task_get(&fx, &id).await })
    };
    let (a_reached, a_release) = backend.after_warm_capture.arm();
    let a = read(&fx);
    a_reached.notified().await;
    let (b_reached, b_release) = backend.cold_winner.arm();
    let b = read(&fx);
    b_reached.notified().await;
    a_release.notify_one();
    let a = a.await.expect("A's read");
    assert_eq!(
        a.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "L2: A retries: {a}"
    );
    b_release.notify_one();
    let b = b.await.expect("B's read");
    assert!(b.to_string().contains(MARKER), "L2: B serves: {b}");
    assert_eq!(fx.gateway.releases() - releases, 1, "L2: one resolver");
}

/// N0: a stored read whose account pre-pass did not run fails closed (no
/// output, retryable) and the broken invariant is counted (M33: the sync
/// site serves on an unfilled memo).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n0_a_read_without_the_account_prepass_fails_closed() {
    let fx = fixture().await;
    let id = finished(&fx, "s1-n0").await;
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    backend
        .skip_account_prepass
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let read = task_get(&fx, &id).await;
    assert!(!read.to_string().contains(MARKER), "N0: output: {read}");
    assert!(read.get("error").is_some(), "N0: refused: {read}");
    assert!(
        backend
            .unfilled_outcome_reads
            .load(std::sync::atomic::Ordering::SeqCst)
            >= 1,
        "N0: the unfilled read is counted"
    );
}

/// Wait for the task to settle and return its committed wire form, read
/// from the store (a stored read would itself judge, and could mask it).
async fn settled_record(fx: &Fx, id: &str) -> Value {
    let store = &fx.state.task_executor.service.store;
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let status = store.status_for_test(id);
        if matches!(
            status,
            Some(
                crate::protocol::tasks::TaskStatus::Completed
                    | crate::protocol::tasks::TaskStatus::Failed
                    | crate::protocol::tasks::TaskStatus::Cancelled
            )
        ) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "the task settles: {status:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let digest = store.owner_digest_for_test(id).expect("an owner");
    let committed = store.get(&digest, id).expect("the settled task");
    serde_json::to_value(committed.task.wire()).expect("JSON")
}

/// A plan task: `steps` as (server, tool) pairs, in order.
async fn plan_task(fx: &Fx, key: &str, steps: &[(&str, &str)]) -> String {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let chain: Vec<Value> = steps
        .iter()
        .map(|(server, tool)| json!({"tool": format!("{server}:{tool}"), "arguments": {}}))
        .collect();
    let made = send(
        fx,
        "tools/call",
        "gateway_execute",
        json!({"name": "gateway_execute", "arguments": {"chain": chain},
            "task": {}, "_meta": meta}),
    )
    .await;
    made.pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a plan task was made: {made}"))
        .to_owned()
}

/// W1 (M14): the grant is revoked between submit and the worker's account
/// step: the worker dispatches nothing to the account backend and records
/// no output from it. Control: the grant live, the output is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_a_grant_revoked_before_the_worker_step_is_refused_there() {
    for revoke in [false, true] {
        let fx = fixture().await;
        let hold = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        super::register_plain_with(
            &fx,
            super::PlainBackend {
                hold: Some(std::sync::Arc::clone(&hold)),
                ..super::PlainBackend::default()
            },
        );
        fx.gateway.answer_next(json!({
            "content": [{"type": "text", "text": MARKER}], "isError": false
        }));
        let id = plan_task(
            &fx,
            &format!("s1-w1-{revoke}"),
            &[(super::PLAIN, "echo"), (BACKEND, TOOL)],
        )
        .await;
        if revoke {
            fx.gateway.revoke_operator_grant_for_test().await;
        }
        hold.add_permits(1);
        let record = settled_record(&fx, &id).await;
        if revoke {
            assert!(!record.to_string().contains(MARKER), "W1: {record}");
            assert!(
                fx.gateway.tool_calls().is_empty(),
                "W1: the account step was sent"
            );
        } else {
            assert!(record.to_string().contains(MARKER), "W1 control: {record}");
        }
    }
}

/// WM1 (M22): a plan [account read, plain echo (held), account read]. While
/// step 2 is held, the operator's own slot relists `read` with an invalid
/// schema. A task run keeps no visibility judgement across its steps, so step
/// 3's caller verdict judges the slot anew and refuses it: the account backend
/// answered one call. Anything that kept step 1's "visible" would send step 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wm1_a_withhold_mid_run_is_seen_at_a_later_step() {
    let fx = fixture().await;
    let hold = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    super::register_plain_with(
        &fx,
        super::PlainBackend {
            hold: Some(std::sync::Arc::clone(&hold)),
            calls: std::sync::Arc::clone(&calls),
        },
    );
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let id = plan_task(
        &fx,
        "s1-wm1",
        &[(BACKEND, TOOL), (super::PLAIN, "echo"), (BACKEND, TOOL)],
    )
    .await;
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while calls.load(std::sync::atomic::Ordering::SeqCst) < 1 {
        assert!(
            std::time::Instant::now() < bound,
            "premise: step 2 arrived and is held"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(fx.gateway.tool_calls().len(), 1, "premise: step 1 was sent");
    let invalid: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": 7}
    }))
    .expect("a tool");
    fx.gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_per_user_tools_for_test(&DirectAccountGateway::operator_binding(), vec![invalid]);
    hold.add_permits(1);
    let _ = settled_record(&fx, &id).await;
    assert_eq!(
        fx.gateway.tool_calls().len(),
        1,
        "WM1: step 3 was sent past the withhold"
    );
}

/// WR1: a resume after an input round, grant live: the resumed dispatch
/// serves on one credential resolution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wr1_a_resume_with_a_live_grant_serves_on_one_resolution() {
    let fx = fixture().await;
    fx.gateway.answer_next(json!({
        "resultType": "input_required",
        "inputRequests": {"confirm": {"method": "elicitation/create",
            "params": {"message": "confirm?", "requestedSchema": {"type": "object", "properties": {}}}}},
        "requestState": "backend-state-wr1"
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-wr1");
    meta["io.modelcontextprotocol/clientCapabilities"]["elicitation"] = json!({});
    let made = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta.clone()}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(&fx, &id).await;
        if got.pointer("/result/status") == Some(&json!("input_required")) {
            break;
        }
        assert!(std::time::Instant::now() < bound, "premise: parked: {got}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let releases = fx.gateway.releases();
    let _ = send(
        &fx,
        "tasks/update",
        &id,
        json!({"taskId": id, "inputResponses": {"confirm": {"action": "accept", "content": {}}},
            "_meta": meta}),
    )
    .await;
    let record = settled_record(&fx, &id).await;
    assert!(
        record.to_string().contains(MARKER),
        "WR1: the resume served: {record}"
    );
    assert_eq!(fx.gateway.releases() - releases, 1, "WR1: one resolution");
}
