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
