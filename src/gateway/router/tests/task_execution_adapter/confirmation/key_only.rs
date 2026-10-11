// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 BIND: a destructive task confirmation binds an API-key-only caller
//! to its key, the same rule `gateway_invoke` continuations already follow
//! (#3451: one key is one principal). Before, such a caller was refused -32003
//! `unbindable_caller` at the challenge, so it could never confirm a task.
//!
//! `key-k1` and `key-k2` carry no identity (`verified_subject` maps neither),
//! so the credential is the only thing that tells them apart.
use super::*;

/// The first call's answer, which must be the confirmation question.
async fn challenged(state: &Arc<AppState>, principal: &str, original: &Value) -> Value {
    let challenge = post(state, principal, original.clone()).await;
    std::assert_eq!(
        challenge.pointer("/result/resultType"),
        Some(&json!("input_required")),
        "{principal}: a key-only caller is asked, not refused as unbindable: {challenge}"
    );
    challenge
}

/// R1: a key-only caller confirms a destructive call on a surfaced tool, the
/// task runs once, and the committed retry names the same task.
#[tokio::test]
async fn a_key_only_caller_confirms_a_destructive_task_once() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = key_only_fixture(&mock).await;
    let original = request("key-only-confirm");
    let challenge = challenged(&state, "key-k1", &original).await;
    let accepted = retry(&original, &challenge, "accept");
    std::assert_eq!(mock.calls(), 0, "challenge must precede dispatch");
    let id = task_id(&post(&state, "key-k1", accepted.clone()).await);
    gate.wait_for_dispatch().await;
    std::assert_eq!(task_id(&post(&state, "key-k1", accepted).await), id);
    gate.release();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-k1", &id).await);
    std::assert_eq!(mock.calls(), 1);
}

/// R2: another key cannot redeem a key-only caller's answered question, and
/// its refused attempt does not spend the grant for the caller it belongs to.
#[tokio::test]
async fn another_key_cannot_redeem_a_key_only_grant_and_does_not_burn_it() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = key_only_fixture(&mock).await;
    let original = request("key-only-owner");
    let challenge = challenged(&state, "key-k1", &original).await;
    let accepted = retry(&original, &challenge, "accept");

    let stolen = post(&state, "key-k2", accepted.clone()).await;
    assert!(
        stolen.pointer("/result/taskId").is_none(),
        "another key redeemed the grant: {stolen}"
    );
    std::assert_eq!(mock.calls(), 0, "a refused redeem must not dispatch");

    let id = task_id(&post(&state, "key-k1", accepted).await);
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-k1", &id).await);
    std::assert_eq!(mock.calls(), 1, "the rightful caller's grant still runs");
}

/// R9: a key-only caller's grant-free repeat of its admitted call is answered
/// with the task it already owns (admission is found under the routed task
/// owner), and the backend is reached once.
#[tokio::test]
async fn a_key_only_grant_free_repeat_returns_the_admitted_task() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, _store) = key_only_fixture(&mock).await;
    let original = request("key-only-repeat");
    let challenge = challenged(&state, "key-k1", &original).await;
    let id = task_id(&post(&state, "key-k1", retry(&original, &challenge, "accept")).await);
    gate.wait_for_dispatch().await;

    let repeat = post(&state, "key-k1", original.clone()).await;
    std::assert_eq!(
        task_id(&repeat),
        id,
        "a grant-free repeat is the admitted task: {repeat}"
    );
    // The other key repeating the same call owns nothing and is asked afresh.
    let foreign = post(&state, "key-k2", original).await;
    assert!(
        foreign.pointer("/result/taskId").is_none(),
        "another key was handed the admitted task: {foreign}"
    );
    gate.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-k1", &id).await);
    std::assert_eq!(mock.calls(), 1);
}
