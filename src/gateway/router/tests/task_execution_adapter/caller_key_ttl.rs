// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7828.FIX.2: a task whose call outlasts the caller key's idle TTL keeps
//! that key. A sweep while the backend still holds the call must not reclaim
//! the state the task writes under the key; once the call is over the key is
//! an idle caller's again and a later sweep reclaims it under the same name.

use super::super::*;
use super::input_round::{STATE_1, answer, ask, done, update, wait_input_required};
use super::support::*;
use crate::gateway::session_lifecycle::{IDLE_TTL, SessionLifecycle, now_unix};

type Reclaimed = Arc<std::sync::Mutex<Vec<String>>>;

/// The suite's state behind `mock`, with a lifecycle that records every key a
/// sweep reclaims.
async fn tracked(
    mock: &Arc<MockBackend>,
) -> (
    Arc<AppState>,
    Arc<SessionLifecycle>,
    Reclaimed,
    tempfile::TempDir,
) {
    let (mut state, store) = fixture_state(&two_principal_auth()).await;
    let lifecycle = Arc::new(SessionLifecycle::new());
    let reclaimed = Reclaimed::default();
    let sink = Arc::clone(&reclaimed);
    lifecycle.register("recorder", move |key| {
        sink.lock().expect("recorder").push(key.to_owned());
    });
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .session_lifecycle = Some(Arc::clone(&lifecycle));
    register(&state, BACKEND, mock);
    (state, lifecycle, reclaimed, store)
}

/// A sweep one idle TTL past the caller's last request, with a call held:
/// the caller is not idle, its task is running.
fn assert_survives_a_sweep(lifecycle: &SessionLifecycle, reclaimed: &Reclaimed) {
    let swept = lifecycle.reap(now_unix().expect("clock after 1970") + IDLE_TTL.as_secs() + 1);
    std::assert_eq!(
        swept,
        0,
        "an idle sweep reclaimed the key of a task still running: {:?}",
        reclaimed.lock().expect("recorder")
    );
}

/// The call is over: the key is tracked again, and a sweep past its new
/// deadline reclaims it, once, under the caller's own key.
fn assert_reclaimed_once_after(lifecycle: &SessionLifecycle, reclaimed: &Reclaimed) {
    std::assert_eq!(
        lifecycle.reap(now_unix().expect("clock after 1970") + 2 * IDLE_TTL.as_secs() + 2),
        1,
        "the key of a finished task is never reclaimed"
    );
    let keys = reclaimed.lock().expect("recorder").clone();
    assert!(
        keys.len() == 1 && keys[0].starts_with("subject:") && keys[0].ends_with(":alice"),
        "reclaimed under a key that is not the caller's: {keys:?}"
    );
}

#[tokio::test]
async fn a_task_running_past_the_idle_ttl_keeps_its_caller_key() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (state, lifecycle, reclaimed, _store) = tracked(&mock).await;

    let created = post(&state, "key-a", task_invoke(40, "ttl-key", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;
    assert_survives_a_sweep(&lifecycle, &reclaimed);

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    assert_reclaimed_once_after(&lifecycle, &reclaimed);
}

/// The resumed call after an input round holds the key the same way.
#[tokio::test]
async fn a_resumed_call_running_past_the_idle_ttl_keeps_its_caller_key() {
    let answers = Answer::Sequence(vec![ask("confirm", STATE_1), done()]);
    let (mock, mut gate) = MockBackend::holding(answers);
    let (state, lifecycle, reclaimed, _store) = tracked(&mock).await;

    let invoke = declaring_elicitation(task_invoke(41, "ttl-resume", json!({})));
    let id = task_id(&post(&state, "key-a", invoke).await);
    gate.wait_for_dispatch().await;
    gate.release();
    wait_input_required(&state, &id).await;

    let acked = post(
        &state,
        "key-a",
        update(42, &id, json!({ "confirm": answer() })),
    )
    .await;
    assert!(
        acked.get("error").is_none(),
        "the answer is accepted: {acked}"
    );
    gate.wait_for_dispatch().await;
    assert_survives_a_sweep(&lifecycle, &reclaimed);

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    assert_reclaimed_once_after(&lifecycle, &reclaimed);
}
