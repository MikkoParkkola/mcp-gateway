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
