// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task's send, and an input round's resumed send, after the grant changed
//! between the listing that showed the tool and the send: a revoked grant
//! sends nothing and settles with the account refusal; a rotated one sends
//! once, under the current grant's credential. Pins today's behaviour: every
//! send path resolves its credential in its own dispatch. Uses the parent's
//! fixture.
use super::*;

/// The task-call shapes the worker dispatches: `gateway_invoke` naming the
/// backend, the surfaced name, and `gateway_execute` single and chain.
const SHAPES: [&str; 4] = ["invoke", "surfaced", "execute", "chain"];

/// One task call of `shape`, keyed `key`: its name and params.
fn task_params(shape: &str, key: &str) -> (String, Value) {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let target = json!({"folder": "inbox"});
    let params = match shape {
        "invoke" => json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": target},
            "task": {}, "_meta": meta}),
        "execute" => json!({"name": "gateway_execute",
            "arguments": {"tool": format!("{BACKEND}:{TOOL}"), "arguments": target},
            "task": {}, "_meta": meta}),
        "chain" => json!({"name": "gateway_execute",
            "arguments": {"chain": [{"tool": format!("{BACKEND}:{TOOL}"), "arguments": target}]},
            "task": {}, "_meta": meta}),
        _ => json!({"name": TOOL, "arguments": target, "task": {}, "_meta": meta}),
    };
    let name = params["name"].as_str().expect("a name").to_owned();
    (name, params)
}

/// Wait for task `id` to settle in the store; its wire form.
async fn settled(fx: &Fx, id: &str, row: &str) -> Value {
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
            "{row}: the task never settled: {status:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let digest = store
        .owner_digest_for_test(id)
        .expect("the task has an owner");
    let committed = store.get(&digest, id).expect("the settled task reads");
    serde_json::to_value(committed.task.wire()).expect("JSON")
}

/// The listing that shows the tool to the operator.
async fn listing_shows_tool(fx: &Fx, row: &str) {
    let listed = send(fx, "tools/list", "", json!({"_meta": modern_meta()})).await;
    assert!(
        listed.to_string().contains(&format!("\"name\":\"{TOOL}\"")),
        "premise {row}: the listing shows {TOOL}: {listed}"
    );
}

/// One live `gateway_invoke` under the grant as it stands, so a later task
/// could reuse its resolution if anything kept one.
async fn warm_send(fx: &Fx, row: &str) {
    let sent = fx.gateway.tool_calls().len();
    let live = send(
        fx,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "_meta": modern_meta()}),
    )
    .await;
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent + 1,
        "premise {row}: the warm call sent once: {live}"
    );
}

/// The binding the vault reads for the operator now.
async fn current_binding(fx: &Fx) -> String {
    fx.state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the grant has a view")
}

/// R9 revoked: listed, then revoked, then the task call: nothing is sent and
/// the call or its task ends with the account refusal a live call gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r9_a_task_after_a_revoke_sends_nothing() {
    for shape in SHAPES {
        let fx = fixture().await;
        listing_shows_tool(&fx, "R9").await;
        warm_send(&fx, "R9").await;
        fx.gateway.revoke_operator_grant_for_test().await;
        let sent = fx.gateway.tool_calls().len();
        let (name, params) = task_params(shape, &format!("r9-revoked-{shape}"));
        let made = send(&fx, "tools/call", &name, params).await;
        let refused = match made.pointer("/result/taskId").and_then(Value::as_str) {
            Some(id) => {
                let task = settled(&fx, id, "R9").await;
                assert_eq!(
                    task.get("status"),
                    Some(&json!("failed")),
                    "R9 {shape}: a task after a revoke did not fail: {task}"
                );
                task
            }
            None => made.clone(),
        };
        assert!(
            refused.get("error").is_some(),
            "R9 {shape}: no account refusal after a revoke: {refused}"
        );
        assert_eq!(
            fx.gateway.tool_calls().len(),
            sent,
            "R9 {shape}: a task sent after the grant was revoked: {refused}"
        );
    }
}

/// R9 rotated: listed, then rotated, then the task call: exactly one send,
/// carrying the current grant's credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r9_a_task_after_a_rotation_sends_once_under_the_new_grant() {
    for shape in SHAPES {
        let fx = fixture().await;
        listing_shows_tool(&fx, "R9").await;
        warm_send(&fx, "R9").await;
        let old = DirectAccountGateway::operator_binding();
        fx.gateway.rotate_operator_grant().await;
        let new = current_binding(&fx).await;
        assert_ne!(new, old, "premise: rotation selects a new slot");
        fx.gateway.rearm_operator_slot_at_for_test(&new);
        let sent = fx.gateway.tool_calls().len();
        let (name, params) = task_params(shape, &format!("r9-rotated-{shape}"));
        let made = send(&fx, "tools/call", &name, params).await;
        let id = made
            .pointer("/result/taskId")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("premise R9 {shape}: a task was made: {made}"))
            .to_owned();
        let task = settled(&fx, &id, "R9").await;
        let calls: Vec<_> = fx.gateway.tool_calls().into_iter().skip(sent).collect();
        assert_eq!(
            calls.len(),
            1,
            "R9 {shape}: other than one send after the rotation: {calls:?} {task}"
        );
        assert_eq!(
            calls[0].1.as_deref(),
            Some(new.as_str()),
            "R9 {shape}: the send did not carry the current grant's credential: {calls:?}"
        );
    }
}

/// R10 rotated (the revoked case is W2 in the parent): the grant rotates
/// during an input round, and the resume never sends under the old grant.
/// Today the resume fails closed: the parked continuation is refused
/// ("continuation rejected") and nothing is sent, which this row pins. A
/// resume that does send must send once, under the current grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r10_a_resume_after_a_rotation_never_sends_under_the_old_grant() {
    let fx = fixture().await;
    let (id, meta) = parked_input_task(&fx).await;
    let old = DirectAccountGateway::operator_binding();
    fx.gateway.rotate_operator_grant().await;
    let new = current_binding(&fx).await;
    assert_ne!(new, old, "premise: rotation selects a new slot");
    fx.gateway.rearm_operator_slot_at_for_test(&new);
    let sent = fx.gateway.tool_calls().len();
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let _ = send(
        &fx,
        "tasks/update",
        &id,
        json!({"taskId": id, "inputResponses": {"confirm": {"action": "accept", "content": {}}},
            "_meta": meta}),
    )
    .await;
    let task = settled(&fx, &id, "R10").await;
    let calls: Vec<_> = fx.gateway.tool_calls().into_iter().skip(sent).collect();
    assert!(
        calls.len() <= 1,
        "R10: more than one resumed send after the rotation: {calls:?} {task}"
    );
    assert!(
        calls
            .iter()
            .all(|call| call.1.as_deref() == Some(new.as_str())),
        "R10: a resumed send did not carry the current grant's credential: {calls:?}"
    );
    if calls.is_empty() {
        assert_eq!(
            task.get("status"),
            Some(&json!("failed")),
            "R10: a resume that sent nothing did not settle refused: {task}"
        );
    }
}
