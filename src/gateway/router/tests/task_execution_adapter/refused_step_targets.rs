// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call the gateway refuses before its backend is no call a backend ran:
//! a refused plan step stays a target (attempted, so stored reads keep
//! re-checking access) but is never a relay replay call, and a refused single
//! call settles as the gateway's own answer, which no reader takes for
//! backend output. The backend's own count is the premise that nothing was
//! sent.
use super::super::*;
use super::stored_result_policy::withhold;
use super::support::*;

/// The task's row once settled, read from the store: a stored read through
/// `tasks/get` judges the caller's current view, so a row whose tool is
/// withheld is refused there, settled or not.
async fn settled_row(
    state: &Arc<AppState>,
    id: &str,
) -> crate::gateway::task_service::CommittedTask {
    use crate::protocol::tasks::TaskStatus;
    let owner = admission_principal();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Ok(row) = state.tasks.get(&owner, id)
                && matches!(
                    row.task.status(),
                    TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                )
            {
                return row;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the task never settled"))
}

/// A single call whose tool is withheld between intake and run settles on
/// the gateway's own answer: the row records the gateway as its author, so
/// no reader takes the stored answer for the backend's.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refused_single_call_settles_as_the_gateways_answer() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store) = state_with(&mock).await;
    let withheld = Arc::clone(&state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        withhold(&withheld, TOOL);
    });
    let created = post(&state, "key-a", task_invoke(1, "refused-single", json!({}))).await;
    let id = task_id(&created);
    let row = settled_row(&state, &id).await;
    std::assert_eq!(mock.calls(), 0, "premise: nothing sent");
    std::assert_eq!(
        row.error_author,
        Some(crate::gateway::task_service::ErrorAuthor::Gateway),
        "the gateway answered this round"
    );
    assert!(
        row.backend_result().is_none() && row.backend_error().is_none(),
        "the gateway's answer is not backend output"
    );
    // On disk: a row this release creates is version 9 and stays so; the
    // author needs version 6 or later, so no rollback boundary moves.
    let file = store.path().join("tasks").join(format!("{id}.json"));
    let value: Value = serde_json::from_slice(&std::fs::read(&file).expect("the row's file"))
        .expect("the row is JSON");
    std::assert_eq!(value["version"], json!(9), "{value}");
    std::assert_eq!(value["errorAuthor"], json!("gateway"), "{value}");
}

/// Control: the same call, nothing withheld, keeps the backend's result.
#[tokio::test]
async fn a_sent_single_call_keeps_the_backends_result() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "sent-single", json!({}))).await;
    let row = settled_row(&state, &task_id(&created)).await;
    std::assert_eq!(mock.calls(), 1);
    std::assert_eq!(row.error_author, None);
    assert!(row.backend_result().is_some(), "the backend's answer");
}

/// A plan with one step sent (alpha) and one withheld between intake and run
/// (beta): the refused step stays a target, a call attempted, so a stored
/// read keeps re-checking access to it; but the relay replay entry, the
/// record a stored read takes "this backend ran it" from, names only alpha.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refused_plan_step_stays_a_target_but_is_no_replay_call() {
    use super::relay_plan_replay::{
        ALPHA, BETA, OTHER_PROSE, PROSE, playbook, playbook_args, rig, task_call,
    };
    let rig = rig(PROSE, OTHER_PROSE, Some(&playbook())).await;
    let withheld = Arc::clone(&rig.state);
    crate::gateway::meta_mcp::visible::seams::before_task_dispatch(move || {
        super::stored_result_policy::withhold_on(&withheld, BETA, TOOL);
    });
    let created = post(
        &rig.state,
        "key-a",
        task_call(
            1,
            "refused-partial",
            "gateway_run_playbook",
            &playbook_args(),
        ),
    )
    .await;
    let id = task_id(&created);
    let row = settled_row(&rig.state, &id).await;
    let joined = rig
        .state
        .task_executor
        .drain(std::time::Duration::from_secs(10))
        .await;
    assert!(
        joined.is_clean(),
        "the settling worker must finish: {joined:?}"
    );
    std::assert_eq!(rig.calls(), (1, 0), "premise: alpha ran, beta was refused");
    let targets = rig.state.task_executor.service.store.targets_for_test(&id);
    std::assert_eq!(
        crate::gateway::task_service::Target::pairs(&targets),
        vec![(ALPHA, TOOL), (BETA, TOOL)],
        "the refused step stays a target"
    );
    let key = crate::security::firewall::StoredKey::Task {
        id: id.clone(),
        revision: row.revision,
    };
    let (_, calls) = rig
        .relay
        .replay_digests(&key)
        .expect("positive control: alpha's step stores a replay entry");
    let servers: Vec<&str> = calls.iter().map(|(_, server, _)| server.as_str()).collect();
    std::assert_eq!(
        servers,
        vec![ALPHA],
        "only the step a backend ran is a replay call"
    );
}
