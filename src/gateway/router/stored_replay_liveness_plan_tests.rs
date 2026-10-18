// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 liveness rows, part 4: a repeated plan task during a
//! custody outage.

use super::*;

/// P8406u (outage on a plan repeat): a repeated keyed `gateway_execute` task
/// answers as its live twin (the same task call, fresh key, `id` masked), with
/// one `idp_refuse`, before the plan carve-out can serve it: no stored output,
/// no step re-run, task count unchanged and no plan executor entered. The
/// plain `tools/call` twin cannot be byte-equal: a plain chain wraps the same
/// refusal as "Chain step N (..) failed: .." (`search/chain_exec.rs:303`) and a
/// task admission refuses before any chain runs. So the plain twin is held to
/// the same code and the same refusal text under that wrapper, exactly.
/// The outage is met before site 5, so M-plan-e9 (E9 off for plans) is equivalent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p8406u_an_unavailable_plan_repeat_answers_retryable() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let made = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406u", true),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let done = wait_terminal(&fx, &id).await;
    assert_eq!(
        done.pointer("/result/status").and_then(Value::as_str),
        Some("completed"),
        "premise: {done}"
    );
    let sent = fx.gateway.tool_calls().len();
    let rows = fx.tasks.service.store.committed_count_for_test();
    let entered = crate::gateway::meta_mcp::plan_entries::count(&fx.meta);
    fx.gateway.fail_custody_for_test(true);
    let refusals = idp_refusals(&fx);
    let again = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406u", true),
    )
    .await;
    assert_eq!(
        idp_refusals(&fx) - refusals,
        1,
        "P8406u: not one idp_refuse: {again}"
    );
    let replay_rows = fx.tasks.service.store.committed_count_for_test() - rows;
    let replay_entries = crate::gateway::meta_mcp::plan_entries::count(&fx.meta) - entered;
    let mut live = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406u-l", true),
    )
    .await;
    let plain = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406u-p", false),
    )
    .await;
    assert_eq!(
        live.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "premise: the live call is retryable: {live}"
    );
    let mut masked = again.clone();
    masked["id"] = Value::Null;
    live["id"] = Value::Null;
    assert_eq!(
        masked, live,
        "P8406u: the repeat is not the live call's answer"
    );
    let message = |answer: &Value| {
        answer
            .pointer("/error/message")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    assert_eq!(
        plain.pointer("/error/code"),
        again.pointer("/error/code"),
        "P8406u: the plain twin has another code: {plain}"
    );
    assert_eq!(
        message(&plain),
        message(&again).map(|inner| format!(
            "JSON-RPC error -32603: Chain step 0 ({BACKEND}:{TOOL}) failed: JSON-RPC error -32603: {inner}"
        )),
        "P8406u: the plain twin is not the repeat's refusal under the chain wrapper: {plain} vs {again}"
    );
    assert!(
        again.pointer("/result/taskId").is_none() && !again.to_string().contains(MARKER),
        "P8406u: the stored plan task was served: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "P8406u: a step was re-run: {again}"
    );
    assert_eq!(
        replay_rows, 0,
        "P8406u: the repeat changed the task count: {again}"
    );
    assert_eq!(
        replay_entries, 0,
        "P8406u: the repeat entered the plan executor: {again}"
    );
}
