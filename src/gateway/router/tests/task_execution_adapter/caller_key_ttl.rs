// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7828.FIX.2: a task whose call outlasts the caller key's idle TTL keeps
//! that key. A sweep while the backend still holds the call must not reclaim
//! the state the task writes under the key; once the call is over the key is
//! an idle caller's again and a later sweep reclaims it under the same name.

use super::super::*;
use super::support::*;
use crate::gateway::session_lifecycle::{IDLE_TTL, SessionLifecycle, now_unix};

#[tokio::test]
async fn a_task_running_past_the_idle_ttl_keeps_its_caller_key() {
    let (mock, mut gate) = MockBackend::holding(Answer::ok());
    let (mut state, _store) = fixture_state(&two_principal_auth()).await;
    let lifecycle = Arc::new(SessionLifecycle::new());
    let reclaimed = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&reclaimed);
    lifecycle.register("recorder", move |key| {
        sink.lock().expect("recorder").push(key.to_owned());
    });
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .session_lifecycle = Some(Arc::clone(&lifecycle));
    register(&state, BACKEND, &mock);

    let created = post(&state, "key-a", task_invoke(40, "ttl-key", json!({}))).await;
    let id = task_id(&created);
    gate.wait_for_dispatch().await;

    // One idle TTL past the creating request, with the call still held: the
    // caller is not idle, its task is running.
    let swept = lifecycle.reap(now_unix() + IDLE_TTL.as_secs() + 1);
    std::assert_eq!(
        swept,
        0,
        "an idle sweep reclaimed the key of a task still running: {:?}",
        reclaimed.lock().expect("recorder")
    );

    gate.release();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);

    // The call is over: the key is tracked again, and a sweep past its new
    // deadline reclaims it, once, under the caller's own key.
    std::assert_eq!(
        lifecycle.reap(now_unix() + 2 * IDLE_TTL.as_secs() + 2),
        1,
        "the key of a finished task is never reclaimed"
    );
    let keys = reclaimed.lock().expect("recorder").clone();
    assert!(
        keys.len() == 1 && keys[0].starts_with("credential:"),
        "reclaimed under a key that is not the caller's: {keys:?}"
    );
}
