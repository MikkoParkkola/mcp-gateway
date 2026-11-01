// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U19 PR3a T19: a queued task is judged by the budget current when it
//! dispatches, and keeps that budget across a later reload (ADR-023). Only
//! the budget differs between N and N+1.

use serde_json::{Value, json};

use super::direct_guards_fixture::send_with_headers;
use super::live_budget_tests::{Fx, KEY, Scope, fixture, governance, reload, spent};
use crate::gateway::meta_mcp::visible::seams;

/// Submit `gateway_invoke alpha read` as a task on `/mcp` under `KEY` and
/// return the last `tasks/get` body once it leaves `working`.
async fn task_result(fx: &Fx, idempotency_key: &str) -> Value {
    let modern = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    });
    let mut submit_meta = modern.clone();
    submit_meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(idempotency_key);
    let submit = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "task": {},
        "_meta": submit_meta,
    });
    let headers = |method: &'static str, name: &'static str| {
        [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", method),
            ("mcp-name", name),
        ]
    };
    let (_, created) = send_with_headers(
        fx,
        "/mcp",
        KEY,
        "tools/call",
        submit,
        None,
        &headers("tools/call", "gateway_invoke"),
    )
    .await;
    let id = created
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the submit was refused: {created}"))
        .to_owned();
    let get_headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tasks/get"),
        ("mcp-name", id.as_str()),
    ];
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let get = json!({"taskId": id, "_meta": modern});
            let (_, body) =
                send_with_headers(fx, "/mcp", KEY, "tasks/get", get, None, &get_headers).await;
            if body.pointer("/result/status").and_then(Value::as_str) != Some("working") {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task never settled")
}

/// T19a: admitted under a budget of 10 with $6 spent, a task whose dispatch
/// meets a reload to 5 is refused: the budget current at dispatch judges it.
#[tokio::test]
async fn t19a_a_queued_task_meets_the_budget_current_at_its_dispatch() {
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| Scope::Key.set(c, Some(10.0)))).await;
        super::live_budget_tests::spend(&fx, 6).await;
        let live = std::sync::Arc::clone(&fx.state.live_config);
        seams::before_task_dispatch(move || {
            live.edit(|c| Scope::Key.set(&mut c.cost_governance, Some(5.0)));
        });
        let got = task_result(&fx, "t19a").await;
        assert!(got.to_string().contains("daily budget exceeded"), "{got}");
        assert!((spent(&fx) - 6.0).abs() < 1e-9, "nothing was spent");
    })
    .await;
}

/// T19b: a task that took its generation at dispatch keeps that budget when a
/// reload lowers it before the call is admitted: 10 at dispatch, $4 spent,
/// 4.5 published after readmission; the call still fits the 10 it took.
#[tokio::test]
async fn t19b_a_dispatching_task_keeps_its_budget_across_a_later_reload() {
    crate::test_day::same_utc_day_async(|| async move {
        let fx = fixture(&governance(|c| Scope::Key.set(c, Some(10.0)))).await;
        super::live_budget_tests::spend(&fx, 4).await;
        let live = std::sync::Arc::clone(&fx.state.live_config);
        seams::after_readmit(move || {
            live.edit(|c| Scope::Key.set(&mut c.cost_governance, Some(4.5)));
        });
        let got = task_result(&fx, "t19b").await;
        assert!(!got.to_string().contains("budget exceeded"), "{got}");
        assert!((spent(&fx) - 5.0).abs() < 1e-9, "the call was spent");
        reload(&fx, |c| Scope::Key.set(c, Some(10.0)));
    })
    .await;
}
