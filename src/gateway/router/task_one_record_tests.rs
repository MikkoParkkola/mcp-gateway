// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 R0 (`tasks/get`): a re-delivery of a stored task result
//! writes one `transport_finalized` record under its own trace, and none under
//! the trace of the call that submitted the task.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{Logged, fixture, invocations, read_task, settled_task, submit_task};

/// The log's `transport_finalized` records, in order.
async fn finalized(fx: &Logged) -> Vec<Value> {
    let _ = invocations(fx).await; // waits until no write is in flight
    std::fs::read_to_string(fx.log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| {
            row["event"] == "response_delivery_attempt"
                && row["response_stage"] == "transport_finalized"
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn r0_a_tasks_get_redelivery_writes_one_record_under_its_own_trace() {
    let fx = fixture(super::Answer::Ok, None).await;
    let id = submit_task(&fx, "r0-task", json!({})).await;
    let settled = settled_task(&fx, &id).await;
    assert_eq!(
        settled.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: the task completed: {settled}"
    );
    let before = finalized(&fx).await;
    let seen: Vec<&str> = before
        .iter()
        .filter_map(|r| r["trace_id"].as_str())
        .collect();
    let again = read_task(&fx, &id).await;
    assert!(again.get("error").is_none(), "premise: delivered: {again}");
    let after = finalized(&fx).await;
    assert_eq!(after.len(), before.len() + 1, "one record for one read");
    let added = &after[after.len() - 1];
    assert_eq!(added["tool"], "tasks/get", "{added}");
    let trace = added["trace_id"].as_str().expect("a trace");
    assert!(!seen.contains(&trace), "{trace} was already used: {seen:?}");
    let mut counts = BTreeMap::new();
    for row in &after {
        *counts.entry(row["trace_id"].to_string()).or_insert(0usize) += 1;
    }
    assert!(counts.values().all(|n| *n == 1), "{counts:?}");
}
