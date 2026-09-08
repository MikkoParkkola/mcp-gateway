// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X13, X14 and X14b — what must be refused, and what must be refused *before*
//! anything durable happens.
//!
//! X13 is `tasks/update`'s `inputResponses` refusal, on the caller's own live
//! task. Design §9 names the reason the existing `.3b` case is not enough: it
//! uses a fabricated id, so it passes on the not-found path alone and would
//! keep passing against an arm that accepts every input response it is given.
//!
//! X14 and X14b are the ordering rows. Design §1 fixes the handoff *after* the
//! destructive gate at `meta_mcp/mod.rs:1626` and before the dispatch arms at
//! `:1635`, which puts authorization (`handlers.rs:1252`), the firewall
//! (`:1303`) and the confirmation gate above the task commit. The prerequisite
//! is recorded as a test rather than asserted in prose: a refusal above the
//! handoff must leave **no record**, and a call that passes every gate must
//! actually reach dispatch, or the negative is vacuous.
//!
//! # The destructive-wrapper half of X14/X14b, as the tree actually stands
//!
//! Design §9 writes X14 against `gateway_run_playbook` as a "destructive
//! wrapper". At `13e97b30` that wrapper is not governed by the gate, and the
//! shape the design describes is not reachable on the task route. Two
//! independent reasons, both in source:
//!
//! * `destructive_confirmation_gate` consults `is_destructive_meta_tool`
//!   (`meta_mcp/mod.rs:1885`), whose set is derived from the meta-tool
//!   annotations. `gateway_run_playbook` and `gateway_execute` are built with
//!   `write_non_idempotent_open_world_annotations`, which sets
//!   `destructive_hint: Some(false)` (`meta_mcp_tool_defs.rs:226,282`). The only
//!   member of the set is `gateway_kill_server` — the annotated one and the
//!   explicit floor — and it is not in design §2's dispatchable-tool list.
//! * A modern request carries no session at all (`handlers.rs:702-707`,
//!   `ORDER.2`), so `require_destructive_confirmation` always gets
//!   `SamplingError::NoSession` ⇒ `Unsupported`, and `ConfirmationPolicy::for_modern()`
//!   turns that into a refusal. The tasks extension is modern-only, so no
//!   task-augmented call can ever reach a *confirmed* destructive gate.
//!
//! So the rows below assert X14 — no record before the gates have run —
//! using the refusals that genuinely apply to a task-eligible tool, plus the
//! actual destructive gate on the one tool that reaches it. An allowed
//! eligible call that passes those gates really dispatches (vacuity control;
//! not X14b). Real X14b — the same genuinely destructive eligible wrapper,
//! CONFIRMED, then backgrounded and settled — is not written: the fixture
//! prerequisite it names cannot exist on a sessionless modern route, and this
//! slice does not add confirmation design. That row remains open.
use super::super::*;
use super::support::*;

// =====================================================================
// adapter design r3 §9 — X13
// =====================================================================

/// Control for X13: an update with no `inputResponses` on the same live task is
/// ACCEPTED.
///
/// Without it, X13's refusal is satisfied by an arm that refuses every
/// `tasks/update` — including the ones `.3c` requires it to acknowledge — and no
/// assertion can tell a targeted refusal from a blanket one.
#[tokio::test]
async fn fixture_control_a_plain_update_of_an_own_live_task_is_acknowledged() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(&state, "key-a", task_invoke(130, "x13-control", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    let ack = post(
        &state,
        "key-a",
        task_method(131, "tasks/update", json!({ "taskId": id.clone() })),
    )
    .await;

    std::assert_eq!(
        ack.pointer("/result/resultType"),
        Some(&json!("complete")),
        "design §5: the update acknowledgement is `{{\"resultType\":\"complete\"}}`; \
         today's arm answers a bare `json!({{}})`: {ack}"
    );

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
}

/// X13 — a non-empty `inputResponses` on the caller's OWN LIVE task is refused,
/// and the task is untouched.
///
/// The task is live and the caller owns it, so no not-found path and no
/// ownership path can answer this: the refusal has to come from the key check
/// design §5 puts in the arm, ahead of the service. `input_required` is
/// unreachable until the A/H round lands, so no key is outstanding and accepting
/// one would be a lie about the task's state.
#[tokio::test]
async fn x13_input_responses_on_an_own_live_task_are_refused_and_write_nothing() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let created = post(&state, "key-a", task_invoke(132, "x13-key", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    let before = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&before),
        "working",
        "precondition: the task is live and the caller owns it, so nothing below \
         can be answered by absence: {before}"
    );

    let refused = post(
        &state,
        "key-a",
        task_method(
            133,
            "tasks/update",
            json!({
                "taskId": id.clone(),
                "inputResponses": { "prompt-1": "yes" }
            }),
        ),
    )
    .await;

    std::assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32602)),
        "an input response matching no outstanding request is refused, on the \
         caller's own live task: {refused}"
    );

    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&after),
        "working",
        "the refused update wrote nothing — the task is exactly where it was: {after}"
    );
    std::assert_eq!(
        after.pointer("/result/ttlMs"),
        before.pointer("/result/ttlMs"),
        "and it did not move the TTL, which is immutable at creation (§13.3): {after}"
    );
    std::assert_eq!(
        after.pointer("/result/pollIntervalMs"),
        before.pointer("/result/pollIntervalMs"),
        "nor the poll interval: {after}"
    );

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
}

// =====================================================================
// adapter design r3 §9 — X14 / X14b
// =====================================================================

/// Whether a refusal left the idempotency key unclaimed.
///
/// The wire's own proof that no record was written. If the refused attempt had
/// committed one, this follow-up with the same key and a different body would be
/// answered `Existing` (a handle to a task nothing dispatched) or `Mismatch`
/// (`-32602`); with no record, admission has never seen the key and the call
/// creates a fresh task.
async fn key_is_still_free(state: &Arc<AppState>, auth: &str, key: &str, id: i64) -> Value {
    post(state, auth, task_invoke(id, key, json!({ "q": "after" }))).await
}

/// X14 — an authorization refusal above the handoff produces no task record.
///
/// `gateway_invoke` is a design §2 dispatchable tool, so this is the eligible
/// shape rather than a corner. The credential is scoped to the mock backend
/// only, so `authorize_tool_target` (`handlers.rs:1252`) refuses on the request
/// thread — above the handoff, and above anything durable.
#[tokio::test]
async fn x14_a_refusal_above_the_handoff_creates_no_task_and_leaves_the_key_free() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let forbidden = register_forbidden(&state);

    let refused = post(
        &state,
        "key-a",
        keyed(
            modern(
                140,
                "tools/call",
                json!({
                    "name": "gateway_invoke",
                    "arguments": {
                        "server": FORBIDDEN_BACKEND, "tool": TOOL, "arguments": {}
                    },
                    "task": {}
                }),
                true,
            ),
            "x14-key",
        ),
    )
    .await;

    assert!(
        refused.get("error").is_some(),
        "a credential scoped away from '{FORBIDDEN_BACKEND}' is refused, task or \
         no task: {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "and it is refused rather than handed a handle. Today the arm at \
         `handlers.rs:1194` mints the record and returns BEFORE the \
         authorization loop at `:1252` ever runs, which is the whole ordering \
         defect this row exists for: {refused}"
    );
    std::assert_eq!(
        forbidden.calls(),
        0,
        "the named backend is registered and answering, so this is the \
         credential's scope refusing and not an absent backend — and it was \
         never reached: {refused}"
    );
    std::assert_eq!(
        mock.calls(),
        0,
        "and nothing was dispatched anywhere else either: {refused}"
    );

    let reused = key_is_still_free(&state, "key-a", "x14-key", 141).await;
    let id = task_id(&reused);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "the refusal wrote no record, so the key was never claimed and this \
         later call created a task of its own: {settled}"
    );
}

/// X14 — the destructive gate itself, on the one meta-tool that reaches it.
///
/// `gateway_kill_server` is the sole member of `DESTRUCTIVE_META_TOOLS` (the
/// annotated one and the floor). The gate at `meta_mcp/mod.rs:1626` runs above
/// the handoff, so a task-augmented call to it must be answered by the gate and
/// must leave no record behind. Today the record is minted at
/// `handlers.rs:1194`, above the admin pre-check at `:1242` and far above the
/// gate — so today this call is answered with a handle to a task that nothing
/// confirmed, which is exactly the refusal-ordering defect.
///
/// The credential is the admin one on purpose: without it the admin gate refuses
/// first and the row would never observe the destructive gate at all.
#[tokio::test]
async fn x14_a_destructive_tool_refused_at_the_gate_creates_no_task_record() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;

    let (status, refused) = post_full(
        &state,
        "key-admin",
        keyed(
            modern(
                142,
                "tools/call",
                json!({
                    "name": "gateway_kill_server",
                    "arguments": { "name": BACKEND },
                    "task": {}
                }),
                true,
            ),
            "x14-destructive",
        ),
    )
    .await;

    assert!(
        refused.get("error").is_some(),
        "a destructive action whose confirmation cannot be obtained is refused \
         ({status}): {refused}"
    );
    assert!(
        refused.pointer("/result/taskId").is_none(),
        "and no handle is issued for it. A task record minted above the gate is a \
         durable record of an action the operator never confirmed: {refused}"
    );
    std::assert_eq!(
        mock.calls(),
        0,
        "the destructive gate refused on the request thread, so nothing was \
         dispatched: {refused}"
    );

    let reused = key_is_still_free(&state, "key-admin", "x14-destructive", 144).await;
    let id = task_id(&reused);
    let settled = poll_until_terminal(&state, "key-admin", &id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "the refusal wrote no record, so the key was never claimed and this \
         later allowed call created a task of its own: {settled}"
    );
}

/// Fixture control: an allowed eligible call that passes every pre-commit
/// gate actually reaches dispatch and settles.
///
/// Without this, both X14 rows are satisfied by a route that refuses everything.
/// The shape is deliberately identical to X14's first row apart from the one
/// thing under test — the backend the credential may reach — so the difference
/// between "refused before the commit" and "committed and dispatched" is that
/// single field and nothing else.
///
/// This is not X14b. X14b is a confirmed destructive eligible wrapper; that
/// row remains open.
#[tokio::test]
async fn fixture_control_an_allowed_eligible_call_dispatches_and_settles() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let forbidden = register_forbidden(&state);

    let created = post(
        &state,
        "key-a",
        keyed(
            modern(
                143,
                "tools/call",
                json!({
                    "name": "gateway_invoke",
                    "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} },
                    "task": {}
                }),
                true,
            ),
            "x14b-key",
        ),
    )
    .await;

    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;

    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "the allowed call really does reach the backend, so X14's \"nothing \
         reached it\" is a decision and not the fixture's default: {settled}"
    );
    std::assert_eq!(
        forbidden.calls(),
        0,
        "and it reached the ALLOWED backend specifically — the other one is \
         registered and answering, so a worker that dispatched to the wrong \
         target could not pass this row on the counter alone: {settled}"
    );
}
