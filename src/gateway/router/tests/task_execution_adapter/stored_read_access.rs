// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1, batch A (test plan s1-t0 + s1-t1): a stored task read
//! judges the task's target against the caller's current view before it
//! delivers stored output. A visibility or account block answers -32601
//! ("Unknown tool"), as an absent name does, whatever the naming; a policy
//! refusal keeps the error a live call gets (lead rule, 2026-10-12).
//!
//! Every row reads its own control first, on the same fixture: while the
//! target is visible, the stored output is delivered.
use super::super::*;
use super::support::*;

/// A blocked stored read answers exactly as the gateway's own absent name
/// does on this route (byte for byte), and never with the stored output.
async fn assert_absent(state: &Arc<AppState>, body: &Value, row: &str) {
    assert!(
        !body.to_string().contains("mock-backend-answered"),
        "{row}: the stored output was delivered: {body}"
    );
    std::assert_eq!(
        body.pointer("/error/code"),
        Some(&json!(-32601)),
        "{row}: a blocked stored read answers -32601: {body}"
    );
    super::stored_result_policy::assert_answers_as_absent(state, body).await;
}

/// A finished `gateway_invoke` task of the mock's tool, its stored output
/// delivered once (the row's control).
async fn finished(state: &Arc<AppState>, key: &str) -> String {
    let created = post(state, "key-a", task_invoke(1, key, json!({ "q": 1 }))).await;
    let id = task_id(&created);
    assert_carries_the_backend_result(&poll_until_terminal(state, "key-a", &id).await);
    assert_carries_the_backend_result(&get_task(state, "key-a", &id).await);
    id
}

fn backend(state: &Arc<AppState>) -> Arc<crate::backend::Backend> {
    state.backends.get(BACKEND).expect("the mock is registered")
}

/// The listing withholds the tool: it is relisted with a structurally
/// invalid schema (P1b), no descriptor block.
fn withhold_by_schema(state: &Arc<AppState>) {
    let invalid: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": 7}
    }))
    .expect("a tool");
    backend(state).store_shared_tools_for_test(vec![invalid]);
}

/// A complete listing that no longer names the tool.
fn delist(state: &Arc<AppState>) {
    let other =
        json!({"name": "other", "description": "Reads.", "inputSchema": {"type": "object"}});
    let _ = backend(state).remember_listed_tools(None, false, &[other]);
}

/// T1 (P1b): HTTP tasks/get, the listing withholds the tool.
#[tokio::test]
async fn t1_tasks_get_answers_absent_once_the_listing_withholds_the_tool() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t1").await;
    withhold_by_schema(&state);
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "T1").await;
}

/// T1d (P1): HTTP tasks/get, a descriptor block. Today this answers the
/// policy's "withheld" error; visibility is judged first, so -32601.
#[tokio::test]
async fn t1d_tasks_get_answers_absent_once_the_tool_is_descriptor_blocked() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t1d").await;
    backend(&state).block_tool_for_test(TOOL);
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "T1d").await;
}

/// T5: the repeated task-augmented call (same key) reaches the stored task
/// (`BeginOutcome::Existing`, shown by the control answering the same task
/// id) and answers absent once the listing withholds the tool.
#[tokio::test]
async fn t5_a_repeated_task_call_answers_absent_once_the_listing_withholds_the_tool() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t5").await;
    let again = post(&state, "key-a", task_invoke(2, "s1-t5", json!({ "q": 1 }))).await;
    std::assert_eq!(
        again.pointer("/result/taskId").and_then(Value::as_str),
        Some(id.as_str()),
        "control: the repeated call reaches the stored task: {again}"
    );
    let sent = mock.calls();
    withhold_by_schema(&state);
    let repeated = post(&state, "key-a", task_invoke(3, "s1-t5", json!({ "q": 1 }))).await;
    // MIK-8361: a repeated gateway_invoke answers as the same call naming a
    // tool the backend does not list (the invoke twin, not the surfaced
    // name's -32601, which the stored-read rows here keep covering).
    let mut absent = task_invoke(3, "s1-t5-twin", json!({ "q": 1 }));
    absent["params"]["arguments"]["tool"] = json!("no_such_tool");
    let twin = post(&state, "key-a", absent).await;
    for answer in [&repeated, &twin] {
        assert!(
            !answer.to_string().contains("mock-backend-answered"),
            "T5: the stored output was delivered: {answer}"
        );
        assert!(
            answer.get("error").is_some_and(Value::is_object)
                || answer.pointer("/result/isError") == Some(&json!(true)),
            "T5: not a refusal: {answer}"
        );
    }
    std::assert_eq!(
        repeated.to_string().replace(TOOL, "<tool>"),
        twin.to_string().replace("no_such_tool", "<tool>"),
        "T5: the repeat answers as the gateway_invoke missing-name twin"
    );
    std::assert_eq!(mock.calls(), sent, "T5: the repeat reached the backend");
}

/// T9: a COMPLETE shared catalogue that no longer lists the tool answers
/// absent (the lead's rule: -32601 even where a live call answers R2's
/// isError).
#[tokio::test]
async fn t9_tasks_get_answers_absent_once_a_complete_catalogue_lacks_the_tool() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t9").await;
    delist(&state);
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "T9").await;
}

/// T9 control (R2-5): a TRUNCATED catalogue without the tool proves nothing
/// about it, so the stored output is still delivered. Pinning on base; M7
/// (truncated counted as complete) turns it red.
#[tokio::test]
async fn t9_a_truncated_catalogue_without_the_tool_still_delivers() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t9t").await;
    delist(&state);
    backend(&state).mark_shared_truncated_for_test();
    assert_carries_the_backend_result(&get_task(&state, "key-a", &id).await);
}

/// Trip the kill switch for the mock's tool, as repeated capability failures
/// do: a policy refusal on the live path.
fn kill(state: &Arc<AppState>) {
    let cfg = crate::kill_switch::budget::CapabilityErrorBudgetConfig::default();
    let switch = state.meta_mcp.kill_switch();
    for _ in 0..cfg.min_samples.max(cfg.window_size) {
        switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
}

/// The error object with every per-call trace id (`gw-` and 36 UUID
/// characters) replaced by one placeholder: two calls never share one.
fn error_masked(body: &Value) -> String {
    const UUID_LEN: usize = 36;
    let text = body.get("error").map(Value::to_string).unwrap_or_default();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("gw-") {
        let after = &rest[at + 3..];
        let is_uuid = after.len() >= UUID_LEN
            && after[..UUID_LEN]
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-');
        out.push_str(&rest[..at + 3]);
        if is_uuid {
            out.push_str("<trace>");
            rest = &after[UUID_LEN..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// T12: the policy refuses AND the listing withholds. Visibility is judged
/// first, as on the live path, so the answer is -32601, never the policy's.
#[tokio::test]
async fn t12_a_withheld_target_answers_absent_even_where_the_policy_also_refuses() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t12").await;
    kill(&state);
    withhold_by_schema(&state);
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "T12").await;
}

/// K2 (lead rule): a policy refusal keeps the live error. Under a kill
/// switch, a stored tasks/get answers the same error, byte for byte (trace
/// ids masked), as a live call by the same caller under that switch.
#[tokio::test]
async fn k2_a_stored_read_under_a_kill_switch_answers_what_a_live_call_answers() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-k2").await;
    kill(&state);
    let live = post(&state, "key-a", sync_invoke(9, json!({ "q": 1 }))).await;
    assert!(
        live.get("error").is_some(),
        "premise: the live call is refused under the kill switch: {live}"
    );
    let stored = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        error_masked(&stored),
        error_masked(&live),
        "K2: the stored read answers what the live call answers"
    );
    assert!(
        !stored.to_string().contains("mock-backend-answered"),
        "K2: no output: {stored}"
    );
}

/// T6: tasks/update with no input responses answers the ordinary ack, with
/// no output member, for a withheld target. Pinning; M10 turns it red.
#[tokio::test]
async fn t6_tasks_update_carries_no_stored_output_for_a_withheld_target() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t6").await;
    let control = post(
        &state,
        "key-a",
        task_method(4, "tasks/update", json!({ "taskId": id })),
    )
    .await;
    withhold_by_schema(&state);
    let update = post(
        &state,
        "key-a",
        task_method(5, "tasks/update", json!({ "taskId": id })),
    )
    .await;
    std::assert_eq!(update.get("result"), control.get("result"), "T6: {update}");
    let mut ack = update.pointer("/result").cloned().unwrap_or_default();
    if let Some(ack) = ack.as_object_mut() {
        // The gateway's own server info rides every result; it is no output.
        ack.remove("_meta");
    }
    std::assert_eq!(
        ack,
        json!({ "resultType": "complete" }),
        "T6: the exact ack, nothing else: {update}"
    );
}

/// T7: tasks/cancel of a finished task answers its ordinary answer, with no
/// stored output, for a withheld target. Pinning; M10 turns it red.
#[tokio::test]
async fn t7_tasks_cancel_carries_no_stored_output_for_a_withheld_target() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t7").await;
    withhold_by_schema(&state);
    let cancel = post(
        &state,
        "key-a",
        task_method(6, "tasks/cancel", json!({ "taskId": id })),
    )
    .await;
    assert!(
        !cancel.to_string().contains("mock-backend-answered"),
        "T7: the cancel answer carries stored output: {cancel}"
    );
    assert!(
        cancel.pointer("/result/result").is_none(),
        "T7: no result member: {cancel}"
    );
}

/// T13: a task parked on an input round shows what the backend asked. Once
/// the listing withholds the tool, the pending requests answer absent.
#[tokio::test]
async fn t13_pending_input_requests_answer_absent_once_the_listing_withholds_the_tool() {
    use super::input_round::{STATE_1, ask, done, parked};
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "s1-t13").await;
    let control = get_task(&state, "key-a", &id).await;
    assert!(
        control.pointer("/result/inputRequests/confirm").is_some(),
        "control: while visible the round shows the backend's question: {control}"
    );
    withhold_by_schema(&state);
    let read = get_task(&state, "key-a", &id).await;
    assert_absent(&state, &read, "T13").await;
    assert!(
        !read.to_string().contains("inputRequests"),
        "T13: the backend's question was delivered: {read}"
    );
}

/// T14: a failed task carrying the peer's own error. Once the listing
/// withholds the tool, the peer's error text answers absent.
#[tokio::test]
async fn t14_a_peer_authored_error_answers_absent_once_the_listing_withholds_the_tool() {
    let mock = MockBackend::answering(Answer::Failure);
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "s1-t14", json!({ "q": 1 }))).await;
    let id = task_id(&created);
    let done = poll_until_terminal(&state, "key-a", &id).await;
    assert!(
        done.to_string().contains("mock-backend-failed"),
        "control: while visible the peer's own error is delivered: {done}"
    );
    withhold_by_schema(&state);
    let read = get_task(&state, "key-a", &id).await;
    assert!(
        !read.to_string().contains("mock-backend-failed"),
        "T14: the peer's error was delivered: {read}"
    );
    assert_absent(&state, &read, "T14").await;
}

/// X1 (lead rule, 2026-10-12): the stated divergence. For an explicit-backend
/// name the live call answers its own refusal (R2's isError, or the
/// dispatch's answer), while the stored read of the same withheld target
/// answers -32601. A tested decision, never an accident.
#[tokio::test]
async fn x1_a_stored_read_answers_absent_where_the_explicit_live_call_answers_otherwise() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-x1").await;
    withhold_by_schema(&state);
    let live = post(&state, "key-a", sync_invoke(8, json!({ "q": 1 }))).await;
    assert_ne!(
        live.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the explicit live call does not answer -32601: {live}"
    );
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "X1").await;
}

/// The second backend a two-target task calls.
const SECOND: &str = "mock-two";

/// The listing of `server` withholds the mock's tool (invalid schema).
fn withhold_on(state: &Arc<AppState>, server: &str) {
    let invalid: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": 7}
    }))
    .expect("a tool");
    state
        .backends
        .get(server)
        .expect("the backend is registered")
        .store_shared_tools_for_test(vec![invalid]);
}

/// A finished two-step `gateway_execute` task: `mock` then `mock-two`.
async fn finished_two_targets(state: &Arc<AppState>, key: &str) -> String {
    let body = keyed(
        modern(
            5,
            "tools/call",
            json!({
                "name": "gateway_execute",
                "arguments": { "chain": [
                    { "tool": format!("{BACKEND}:{TOOL}"), "arguments": {} },
                    { "tool": format!("{SECOND}:{TOOL}"), "arguments": {} }
                ] },
                "task": {}
            }),
            true,
        ),
        key,
    );
    let created = post(state, "key-a", body).await;
    let id = task_id(&created);
    let done = poll_until_terminal(state, "key-a", &id).await;
    std::assert_eq!(status_of(&done), "completed", "premise: {done}");
    let control = get_task(state, "key-a", &id).await;
    assert!(
        control.to_string().contains("mock-backend-answered"),
        "control: both targets visible, the output is delivered: {control}"
    );
    id
}

/// T15: two targets, one withheld, in both orders: any withheld target
/// answers absent (M28, only the first target judged, fails the first case).
#[tokio::test]
async fn t15_a_two_target_task_answers_absent_when_either_target_is_withheld() {
    for (case, withheld) in [("second withheld", SECOND), ("first withheld", BACKEND)] {
        // Every key reaches both backends: admission is never what it observes.
        let (state, _store) = two_backend_state().await;
        let id = finished_two_targets(&state, &format!("s1-t15-{withheld}")).await;
        withhold_on(&state, withheld);
        assert_absent(&state, &get_task(&state, "key-a", &id).await, case).await;
    }
}

/// Fixture state where every key reaches both backends, each a counted mock.
async fn two_backend_state() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let mut auth = two_principal_auth();
    for key in &mut auth.api_keys {
        key.backends.push(SECOND.to_string());
    }
    let (state, store) = fixture_state(&auth).await;
    register(&state, BACKEND, &MockBackend::answering(Answer::ok()));
    register(&state, SECOND, &MockBackend::answering(Answer::ok()));
    (state, store)
}

/// Install playbook `pb` with `steps`.
fn install(state: &Arc<AppState>, steps: &Value) {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0", "name": "pb", "description": "stored-read rows", "steps": steps
    }))
    .expect("the fixture playbook deserialises");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    state.meta_mcp.set_playbook_engine(engine);
}

fn step(name: &str, server: &str) -> Value {
    json!({ "name": name, "tool": TOOL, "server": server, "arguments": {} })
}

/// A finished `gateway_run_playbook` task of `pb`, its output delivered once.
async fn finished_playbook(state: &Arc<AppState>, key: &str) -> String {
    let body = keyed(
        modern(
            7,
            "tools/call",
            json!({ "name": "gateway_run_playbook", "arguments": { "name": "pb" }, "task": {} }),
            true,
        ),
        key,
    );
    let created = post(state, "key-a", body).await;
    let id = task_id(&created);
    let done = poll_until_terminal(state, "key-a", &id).await;
    std::assert_eq!(status_of(&done), "completed", "premise: {done}");
    let control = get_task(state, "key-a", &id).await;
    assert!(
        control.to_string().contains("mock-backend-answered"),
        "control: every target visible, the output is delivered: {control}"
    );
    id
}

/// T22 (a2a-1, MIK-8406): the judged targets are the RECORDED ones. A step
/// removed from the definition after the task completed is still judged:
/// withholding its tool blocks the read.
#[tokio::test]
async fn t22_a_recorded_step_removed_from_the_playbook_still_blocks_the_read() {
    let (state, _store) = two_backend_state().await;
    install(&state, &json!([step("s1", BACKEND), step("s2", SECOND)]));
    let id = finished_playbook(&state, "s1-t22").await;
    install(&state, &json!([step("s1", BACKEND)]));
    withhold_on(&state, SECOND);
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "T22").await;
}

/// T23 (a2a-1, MIK-8406): a conditional step that never ran is not recorded,
/// so withholding its tool does not block the read. Pinning on base; a
/// mutant judging the definition's steps instead of the record turns it red.
#[tokio::test]
async fn t23_an_unrun_conditional_step_does_not_block_the_read() {
    let (state, _store) = two_backend_state().await;
    let mut skipped = step("s2", SECOND);
    skipped["condition"] = json!("false");
    install(&state, &json!([step("s1", BACKEND), skipped]));
    let id = finished_playbook(&state, "s1-t23").await;
    let recorded = state.task_executor.service.store.targets_for_test(&id);
    assert!(
        recorded.iter().all(|t| t.server != SECOND),
        "premise: the unrun step is not recorded: {recorded:?}"
    );
    withhold_on(&state, SECOND);
    let read = get_task(&state, "key-a", &id).await;
    assert!(
        read.to_string().contains("mock-backend-answered") && read.get("error").is_none(),
        "T23: an unrun step's withheld tool blocked the read: {read}"
    );
}

/// Working control (M32): a task still running under a withheld target has
/// no output yet, so its read answers the ordinary status envelope, never a
/// refusal.
#[tokio::test]
async fn a_working_task_under_a_withheld_target_answers_its_status() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "s1-wc", json!({ "q": 1 }))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;
    withhold_by_schema(&state);
    let read = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&read), "working", "working control: {read}");
    assert!(
        read.get("error").is_none(),
        "working control refused: {read}"
    );
    gate.release_all();
}

/// Cancelled control (M32): a cancelled task carries no output, so its read
/// under a withheld target answers the ordinary status envelope.
#[tokio::test]
async fn a_cancelled_task_under_a_withheld_target_answers_its_status() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "s1-cc", json!({ "q": 1 }))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;
    let _ = post(
        &state,
        "key-a",
        task_method(6, "tasks/cancel", json!({ "taskId": id })),
    )
    .await;
    gate.release_all();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "cancelled", "premise: {settled}");
    withhold_by_schema(&state);
    let read = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&read), "cancelled", "cancelled control: {read}");
    assert!(
        read.get("error").is_none(),
        "cancelled control refused: {read}"
    );
}

/// F3 (M34): a Created answer never carries backend output; one built from a
/// seeded completed record trips the check.
#[tokio::test]
async fn f3_a_created_answer_carrying_output_trips_the_check() {
    use crate::gateway::task_service::execution::{BeginOutcome, CREATED_SERVING_OUTPUT};
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-f3").await;
    let store = &state.task_executor.service.store;
    let digest = store.owner_digest_for_test(&id).expect("an owner");
    let completed = store.get(&digest, &id).expect("the completed record");
    let before = CREATED_SERVING_OUTPUT.load(std::sync::atomic::Ordering::SeqCst);
    let _ = BeginOutcome::Created(completed).into_response(crate::protocol::RequestId::Number(1));
    assert!(
        CREATED_SERVING_OUTPUT.load(std::sync::atomic::Ordering::SeqCst) > before,
        "F3: the check fired"
    );
}

/// T9c (M35): the backend's catalogue was never listed (a fresh instance
/// under the same name): it proves nothing about the tool, so the read is
/// judged on the other reasons and serves.
#[tokio::test]
async fn t9c_a_never_listed_catalogue_still_delivers() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t9c").await;
    assert!(state.backends.remove(BACKEND), "premise: removed");
    register(&state, BACKEND, &mock);
    assert_carries_the_backend_result(&get_task(&state, "key-a", &id).await);
}

/// T9d: a listed, COMPLETE, empty catalogue lacks the tool: -32601.
#[tokio::test]
async fn t9d_a_complete_empty_catalogue_answers_absent() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let id = finished(&state, "s1-t9d").await;
    let _ = backend(&state).remember_listed_tools(None, false, &[]);
    assert_absent(&state, &get_task(&state, "key-a", &id).await, "T9d").await;
}

/// T16 (M25, lead ruling 2026-10-12): the caller's identity grant for the
/// target is withdrawn after the task ran. The stored read answers exactly
/// what the live call by the same caller answers, and both write a
/// grant-denial record. Control: while the grant stands, the stored task is
/// delivered.
#[tokio::test]
async fn t16_a_grant_withdrawn_after_the_task_ran_answers_as_the_live_call() {
    use crate::gateway::meta_mcp::grant_audit_fixture::{decisions, grants};
    use crate::security::audit::AuditFailurePolicy;
    let row =
        super::grant_decisions::armed(true, false, AuditFailurePolicy::BestEffort, |m| m).await;
    let created = post(
        &row.state,
        "key-a",
        super::grant_decision_tasks::as_task(super::grant_decisions::personal_invoke(1), "s1-t16"),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&row.state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "control: {settled}");
    let control = get_task(&row.state, "key-a", &id).await;
    assert!(
        control.get("error").is_none(),
        "control: delivered: {control}"
    );
    row.state.meta_mcp.set_identity_grants(grants(vec![]));
    // MIK-7692: the live denial is not in a repeat scope, so it is always
    // written; the stored denial is a changed decision (the last write for
    // this task and caller was "ok"), so it is written at once.
    let before = decisions(&row.dir).len();
    let live = post(
        &row.state,
        "key-a",
        super::grant_decisions::personal_invoke(9),
    )
    .await;
    assert!(
        live.get("error").is_some(),
        "T16: premise: the live call is refused: {live}"
    );
    let after_live = decisions(&row.dir);
    std::assert_eq!(
        after_live.len(),
        before + 1,
        "T16: the live denial is recorded: {after_live:#?}"
    );
    std::assert_eq!(
        after_live[before]["outcome"],
        json!("denied"),
        "T16: {after_live:#?}"
    );
    let stored = get_task(&row.state, "key-a", &id).await;
    std::assert_eq!(
        error_masked(&stored),
        error_masked(&live),
        "T16: the stored read answers what the live call answers"
    );
    let after_stored = decisions(&row.dir);
    std::assert_eq!(
        after_stored.len(),
        before + 2,
        "T16: the stored denial is recorded at once: {after_stored:#?}"
    );
    std::assert_eq!(
        after_stored[before + 1]["outcome"],
        json!("denied"),
        "T16: {after_stored:#?}"
    );
    // MIK-8361: the live call answers as an undefined capability does, for
    // the same caller (made last, so it moves none of the counts above).
    let mut undefined = super::grant_decisions::personal_invoke(10);
    let personal = undefined["params"]["arguments"]["tool"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    undefined["params"]["arguments"]["tool"] = json!("no_such_capability");
    let twin = post(&row.state, "key-a", undefined).await;
    std::assert_eq!(
        error_masked(&live).replace(&personal, "<tool>"),
        error_masked(&twin).replace("no_such_capability", "<tool>"),
        "T16: the live call answers as the undefined capability"
    );
}

/// MIK-8361 under MIK-8392: only a refusal that depends on the capability
/// existing (admin rule, identity grant) answers as the undefined capability.
/// A kill switch on the capability server keeps its own answer on the stored
/// read, byte for byte the live call's.
#[tokio::test]
async fn t16k_a_killed_capability_keeps_the_kill_switch_answer_on_the_stored_read() {
    use crate::security::audit::AuditFailurePolicy;
    let row =
        super::grant_decisions::armed(true, false, AuditFailurePolicy::BestEffort, |m| m).await;
    let created = post(
        &row.state,
        "key-a",
        super::grant_decision_tasks::as_task(super::grant_decisions::personal_invoke(1), "s1-t16k"),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&row.state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "control: {settled}");
    let call = super::grant_decisions::personal_invoke(9);
    let server = call["params"]["arguments"]["server"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    row.state.meta_mcp.kill_switch().kill(&server);
    let live = post(&row.state, "key-a", call).await;
    assert!(
        live.pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("kill switch")),
        "T16k: premise: the live call meets the kill switch: {live}"
    );
    let stored = get_task(&row.state, "key-a", &id).await;
    std::assert_eq!(
        error_masked(&stored),
        error_masked(&live),
        "T16k: the stored read keeps the kill switch's own answer"
    );
}

#[path = "stored_read_access_findings.rs"]
mod findings;
