// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! X7 and X8 — how a dispatch that did not simply succeed is written down.
//!
//! X7 is the interim `input_required` round: design §4 moves its classification
//! into I1 because `dispatch_below_gate` can return that shape on day one, and
//! the rule is that such a round is never persisted as `input_required` and
//! never left `working`.
//!
//! X8 is the settlement filter: `error_response_preserving_status`
//! (`meta_mcp/mod.rs:173-211`) writes `authz::HTTP_STATUS_DATA_KEY` into a
//! refusal's `data` so the HTTP layer can honour it. Committed, every later
//! `tasks/get` would serve that internal channel to the client. The row carries
//! its own producer control, because "the key is absent" is satisfied both by a
//! filter that works and by a fixture that never produced the key at all.
use super::super::*;
use super::support::*;

/// The `_meta` keys design §4 requires an interrupted or abandoned execution to
/// carry, spelled as the wire spells them.
const EXECUTION_OUTCOME: &str = "/result/result/_meta/io.mcp-gateway~1executionOutcome";
const REASON: &str = "/result/result/_meta/io.mcp-gateway~1reason";

/// The internal HTTP-status channel (`crate::gateway::authz::HTTP_STATUS_DATA_KEY`).
const HTTP_STATUS_DATA_KEY: &str = "gateway_http_status";

// =====================================================================
// adapter design r3 §9 — X7
// =====================================================================

/// Watch a task to a terminal status, failing if it is ever seen claiming an
/// input round nobody can answer.
///
/// `poll_until_terminal` alone cannot make this assertion: `input_required` is
/// not terminal, so a task parked in it would spin the poll out rather than fail
/// with the reason.
async fn settle_without_ever_claiming_input(
    state: &Arc<AppState>,
    principal: &str,
    id: &str,
) -> Value {
    for _ in 0..5_000 {
        let fetched = get_task(state, principal, id).await;
        let status = status_of(&fetched);
        assert_ne!(
            status, "input_required",
            "design §4: an interim round is never PERSISTED as `input_required` — \
             the status exists in the model but is unreachable until the A/H \
             elicitation flow, and a task parked in it is a round nobody will \
             ever answer: {fetched}"
        );
        if is_terminal(&status) {
            return fetched;
        }
        tokio::task::yield_now().await;
    }
    panic!("the task never settled; an interim round must not leave it `working` either");
}

/// Assert the settled task is the completed tool-error design §4 specifies.
fn assert_abandoned_round(fetched: &Value) {
    std::assert_eq!(
        status_of(fetched),
        "completed",
        "design §4: an abandoned round is a COMPLETED tool-error result, not \
         `failed` — `failed` is the JSON-RPC dispatch failure and keeps its own \
         row: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/isError"),
        Some(&json!(true)),
        "the completed result is an error result: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer(EXECUTION_OUTCOME),
        Some(&json!("unknown")),
        "the backend stopped mid-effect, so the execution outcome is `unknown` \
         and not `not_executed`: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer(REASON),
        Some(&json!("input_round_unavailable")),
        "the reason names what actually happened — a continuation envelope was \
         minted for a round nobody will answer: {fetched}"
    );
}

/// X7 — a well-formed interim round settles as an abandoned completion.
#[tokio::test]
async fn x7_a_well_formed_interim_round_settles_completed_with_an_abandoned_reason() {
    // The shape `InputRequired::from_result` accepts (`protocol/mrtr.rs`): a
    // claimed input round carrying the backend's own opaque state.
    let mock = MockBackend::answering(Answer::Result(json!({
        "resultType": "input_required",
        "requestState": "opaque-backend-state"
    })));
    let (state, _store) = state_with(&mock).await;

    let created = post(
        &state,
        "key-a",
        declaring_elicitation(task_invoke(70, "x7-well-formed", json!({}))),
    )
    .await;
    let id = task_id(&created);

    let fetched = settle_without_ever_claiming_input(&state, "key-a", &id).await;
    assert_abandoned_round(&fetched);
    assert!(
        !serde_json::to_string(&fetched)
            .unwrap_or_default()
            .contains("opaque-backend-state"),
        "the backend's opaque continuation state is never relayed to the client: {fetched}"
    );
}

/// X7 — the malformed round, which is the half that decides the classifier.
///
/// `InputRequired::from_result` returns `None` for a round it cannot parse
/// (`protocol/mrtr.rs:218-235`). A classifier keyed on THAT would see no round
/// here and commit the backend's half-finished object as a finished result. The
/// classifier keys on `claims_input_required` — the backend's own claim — so a
/// malformed question is abandoned exactly like a well-formed one.
#[tokio::test]
async fn x7_a_malformed_interim_round_is_abandoned_and_never_committed_as_a_result() {
    // Claims the round, carries neither a usable state nor a usable question.
    let mock = MockBackend::answering(Answer::Result(json!({
        "resultType": "input_required",
        "requestState": { "not": "a string" }
    })));
    let (state, _store) = state_with(&mock).await;

    let created = post(
        &state,
        "key-a",
        declaring_elicitation(task_invoke(71, "x7-malformed", json!({}))),
    )
    .await;
    let id = task_id(&created);

    let fetched = settle_without_ever_claiming_input(&state, "key-a", &id).await;
    assert_abandoned_round(&fetched);
    assert_ne!(
        fetched.pointer("/result/result/resultType"),
        Some(&json!("input_required")),
        "the backend's own unparseable round must not be handed to the client as \
         the task's finished result: {fetched}"
    );
}

// =====================================================================
// adapter design r3 §9 — X8
// =====================================================================

/// A playbook whose single step names a backend the caller's credential cannot
/// reach.
///
/// Chosen because it is the one shape whose refusal happens INSIDE the worker.
/// `backend_tool_targets_for_call` (`router/authorization.rs:19-39`) derives no
/// targets for `gateway_run_playbook` — a playbook's steps are not in the
/// request — so the router's pre-dispatch loop has nothing to check and the
/// invoke chokepoint is the only authorizer. That refusal is
/// `Error::Forbidden`, which is the one variant
/// `error_response_preserving_status` stamps the HTTP-status key onto.
fn forbidden_playbook() -> crate::playbook::PlaybookEngine {
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "reach-the-vault",
        "description": "one step, at a backend this credential may not reach",
        "steps": [
            { "name": "step", "tool": TOOL, "server": FORBIDDEN_BACKEND, "arguments": {} }
        ]
    }))
    .expect("the fixture playbook must deserialise");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    engine
}

fn run_playbook_params() -> Value {
    json!({
        "name": "gateway_run_playbook",
        "arguments": { "name": "reach-the-vault" }
    })
}

/// Control for X8: the refusal really does carry the internal HTTP-status key.
///
/// Not an acceptance criterion. Without it, X8's "the key is absent from the
/// polled task" is satisfied by a filter that works AND by a fixture whose
/// refusal never carried the key in the first place, and no assertion can tell
/// those apart. If this control fails, X8 below is measuring nothing and the
/// producer — not the filter — is what needs fixing.
#[tokio::test]
async fn fixture_control_a_synchronous_refusal_carries_the_internal_http_status_key() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let forbidden = register_forbidden(&state);
    state.meta_mcp.set_playbook_engine(forbidden_playbook());

    let body = post(
        &state,
        "key-a",
        modern(80, "tools/call", run_playbook_params(), true),
    )
    .await;

    assert!(
        body.get("error").is_some(),
        "the step's backend is outside this credential's scope, so the chokepoint \
         refuses: {body}"
    );
    assert!(
        body.pointer(&format!("/error/data/{HTTP_STATUS_DATA_KEY}"))
            .is_some(),
        "`error_response_preserving_status` stamps `{HTTP_STATUS_DATA_KEY}` onto a \
         `Forbidden` refusal (`meta_mcp/mod.rs:184-186`). If this is absent, the \
         fixture no longer produces the key X8 exists to strip, and X8 has become \
         vacuous: {body}"
    );
    std::assert_eq!(
        forbidden.calls(),
        0,
        "the step's backend is registered and answering, so the refusal is the \
         chokepoint's and not a missing backend — and the step still reached it \
         zero times: {body}"
    );
    std::assert_eq!(
        mock.calls(),
        0,
        "and the step did not land on the reachable backend instead: {body}"
    );
}

/// X8 — a `failed` task keeps its error's `code` and `message` and loses the
/// gateway's internal HTTP-status channel.
#[tokio::test]
async fn x8_a_failed_task_keeps_code_and_message_and_drops_the_http_status_key() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let forbidden = register_forbidden(&state);
    state.meta_mcp.set_playbook_engine(forbidden_playbook());

    let mut params = run_playbook_params();
    params["task"] = json!({});
    let created = post(
        &state,
        "key-a",
        keyed(modern(81, "tools/call", params, true), "x8-key"),
    )
    .await;
    let id = task_id(&created);

    let fetched = poll_until_terminal(&state, "key-a", &id).await;

    std::assert_eq!(
        status_of(&fetched),
        "failed",
        "a dispatch that answered with a JSON-RPC error settles `failed`, with the \
         error object preserved (design §4): {fetched}"
    );
    assert!(
        fetched
            .pointer("/result/error/code")
            .and_then(Value::as_i64)
            .is_some(),
        "the error's code survives into the polled task: {fetched}"
    );
    assert!(
        fetched
            .pointer("/result/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| !message.is_empty()),
        "the error's message survives into the polled task: {fetched}"
    );
    assert!(
        fetched
            .pointer(&format!("/result/error/data/{HTTP_STATUS_DATA_KEY}"))
            .is_none(),
        "design §4: `data`'s HTTP-status key is stripped before commit. It is the \
         gateway's own transport channel; committed, every later `tasks/get` \
         would serve it to the client forever: {fetched}"
    );
    assert!(
        !serde_json::to_string(&fetched)
            .unwrap_or_default()
            .contains(HTTP_STATUS_DATA_KEY),
        "and it is not relocated to somewhere else in the task view either: {fetched}"
    );
    std::assert_eq!(
        forbidden.calls(),
        0,
        "the refused step never reached the backend it named: {fetched}"
    );
    std::assert_eq!(mock.calls(), 0, "nor any other: {fetched}");
}
