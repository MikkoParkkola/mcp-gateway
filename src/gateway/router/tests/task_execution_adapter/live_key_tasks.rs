// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K15: queued and continued work re-checks the API key it was created with
//! against the key table current when it dispatches. A key a reload removed,
//! or narrowed so the backend is out of its scope, refuses the queued task's
//! first dispatch and an input round's continuation, with no backend call.
//! A task whose key the reload keeps still runs.
use super::super::*;
use super::input_round::{STATE_1, answer, ask, done, parked, update};
use super::support::*;

/// The fixture's key list.
type Keys = Vec<crate::config::ApiKeyConfig>;

/// Reload `edit` of the fixture's two-principal key table.
fn reload_keys(state: &Arc<AppState>, edit: impl FnOnce(Keys) -> Keys) {
    let mut config = (*state.live_config.get()).clone();
    let mut auth = two_principal_auth();
    auth.api_keys = edit(auth.api_keys);
    config.auth = auth;
    state.live_config.set(config);
}

fn without(keys: Keys, name: &str) -> Keys {
    keys.into_iter().filter(|k| k.name != name).collect()
}

fn remove_key_a(keys: Keys) -> Keys {
    without(keys, "principal-a")
}

fn remove_key_b(keys: Keys) -> Keys {
    without(keys, "principal-b")
}

/// key-a re-issued under a new secret that keeps its name and states its old
/// principal explicitly: the stored principal matches, the credential does
/// not.
fn replace_key_a_keeping_its_principal(keys: Keys) -> Keys {
    keys.into_iter()
        .map(|mut key| {
            if key.name == "principal-a" {
                key.key_sha256 = Some(crate::config::api_key_digest_spec(b"key-a-reissued"));
                key.principal = Some(
                    crate::gateway::auth::principal_of("key-a")
                        .storage_form()
                        .to_owned(),
                );
            }
            key
        })
        .collect()
}

fn narrow_key_a(keys: Keys) -> Keys {
    keys.into_iter()
        .map(|mut key| {
            if key.name == "principal-a" {
                key.backends = vec![FORBIDDEN_BACKEND.to_owned()];
            }
            key
        })
        .collect()
}

/// The committed record of `task`, once terminal, read as its owner (the
/// owner's key may be gone, so not through the route).
async fn settled(state: &Arc<AppState>, task: &str) -> String {
    let owner = admission_principal();
    tokio::time::timeout(crate::test_wait::HANG_BOUND, async {
        loop {
            if let Ok(committed) = state.tasks.get(&owner, task) {
                use crate::protocol::tasks::TaskStatus;
                if matches!(
                    committed.task.status(),
                    TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                ) {
                    return format!("{:?}", committed.task);
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the task never settled"))
}

/// K15 (i): a reload between a task's admission and its first dispatch that
/// removes, or narrows, the creating key refuses the dispatch: no backend call.
#[tokio::test]
async fn k15_a_queued_task_of_a_removed_or_narrowed_key_is_refused_at_dispatch() {
    for (label, edit) in [
        ("removed", remove_key_a as fn(Keys) -> Keys),
        ("narrowed", narrow_key_a),
        (
            "re-issued, principal kept",
            replace_key_a_keeping_its_principal,
        ),
    ] {
        let mock = MockBackend::answering(Answer::ok());
        let (state, _store) = state_with(&mock).await;
        let reloaded = Arc::clone(&state);
        crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
            reload_keys(&reloaded, edit);
        });
        let created = post(
            &state,
            "key-a",
            task_invoke(1, &format!("k15-{label}"), json!({})),
        )
        .await;
        let record = settled(&state, &task_id(&created)).await;
        std::assert_eq!(mock.calls(), 0, "{label}: the backend was called: {record}");
    }
}

/// K15 control: a reload that keeps the creating key lets the task run.
#[tokio::test]
async fn k15_a_queued_task_of_a_kept_key_runs() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let reloaded = Arc::clone(&state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        reload_keys(&reloaded, remove_key_b);
    });
    let created = post(&state, "key-a", task_invoke(1, "k15-kept", json!({}))).await;
    let settled = poll_until_terminal(&state, "key-a", &task_id(&created)).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(mock.calls(), 1, "{settled}");
}

/// K15 (ii): an input round answered while the key is live, with a reload
/// that removes the key landing after `Accepted` and before the continuation
/// is redeemed: the continuation is refused, and the backend is not called a
/// second time.
#[tokio::test]
async fn k15_a_continuation_after_its_key_is_removed_is_refused() {
    use crate::gateway::task_service::execution::resume_seams::{ResumePoint, pause_at_for_test};
    for (label, edit) in [
        ("removed", remove_key_a as fn(Keys) -> Keys),
        (
            "re-issued, principal kept",
            replace_key_a_keeping_its_principal,
        ),
    ] {
        let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
        let (state, _store) = state_with(&mock).await;
        let id = parked(&state, &format!("k15-continued-{label}")).await;
        std::assert_eq!(mock.calls(), 1, "{label}: premise: the first round ran");
        let pause = pause_at_for_test(ResumePoint::BeforeRedeem);
        let resuming = {
            let (state, id) = (Arc::clone(&state), id.clone());
            tokio::spawn(async move {
                post(
                    &state,
                    "key-a",
                    update(2, &id, json!({ "confirm": answer() })),
                )
                .await
            })
        };
        tokio::time::timeout(crate::test_wait::HANG_BOUND, pause.reached())
            .await
            .expect("the resume worker reached the point before redeeming");
        reload_keys(&state, edit);
        pause.release();
        drop(pause);
        let _ = resuming.await;
        let record = settled(&state, &id).await;
        std::assert_eq!(
            mock.calls(),
            1,
            "{label}: the continuation reached the backend: {record}"
        );
    }
}
