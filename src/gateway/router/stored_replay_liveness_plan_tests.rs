// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 liveness rows, part 4: a repeated plan task during a
//! custody outage.

use super::*;

/// P8406u (outage on a plan repeat): a repeated keyed `gateway_execute` task
/// answers as the live call (fresh key, `id` masked) with one `idp_refuse`,
/// before the plan carve-out can serve it: no stored output, no step re-run.
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
    let mut live = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("p8406u-l", true),
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
    assert!(
        again.pointer("/result/taskId").is_none() && !again.to_string().contains(MARKER),
        "P8406u: the stored plan task was served: {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "P8406u: a step was re-run: {again}"
    );
}
