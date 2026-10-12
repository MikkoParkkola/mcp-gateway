// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 gap row (lead ruling 2026-10-12), on MIK-8392 STORED.1's code:
//! the operator's managed account turns Unavailable (custody fails) while its
//! tool stays in the warm catalogue. The live call is refused, yet the
//! repeated task-augmented plan call is answered with the stored task:
//! `refuse_stored_repeat` judges only the catalogue, and plan tools skip
//! STORED.2's account step. MIK-8406 flips this row to the live twin's
//! answer. No network: custody outcomes are scripted.

use serde_json::{Value, json};

use super::{BACKEND, TOOL, answer_marker, execute_params, fixture, meta, send, wait_terminal};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plan_repeat_unavailable_account_is_mik_8406_gap() {
    let fx = fixture(false).await;
    answer_marker(&fx);
    let made = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("gap-u", true),
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
        "premise: the plan task completed: {done}"
    );
    let sent = fx.gateway.tool_calls().len();

    fx.gateway.fail_custody_for_test(true);
    let live = send(
        &fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
               "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
               "_meta": meta(None, false)}),
    )
    .await;
    assert!(
        live.get("error").is_some() || live.pointer("/result/isError") == Some(&json!(true)),
        "premise: the live twin is refused while the account is Unavailable: {live}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "premise: the live twin sent nothing"
    );

    let again = send(
        &fx,
        "tools/call",
        "gateway_execute",
        execute_params("gap-u", true),
    )
    .await;
    eprintln!("gap-u live: {live}\ngap-u repeat: {again}");
    assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "the gap has closed: the repeat is no longer answered with the stored task \
         (MIK-8406 flips this row to the live twin's answer): {again}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "a step was re-run: {again}"
    );
}
