// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call refused inside its backend's own send (a secret rule that cannot be
//! applied, before any byte leaves) is no call a backend ran, on the task
//! path as on a single call: a refused single call settles as the gateway's
//! answer, and a refused plan step is never a relay replay call. The mock's
//! own count is the premise that nothing was sent.
use super::super::*;
use super::support::*;

/// A `query` rule: no transport can carry it, so the send refuses it.
fn query_rule() -> crate::secret_injection::CredentialRule {
    crate::secret_injection::CredentialRule {
        name: "api".to_string(),
        credential_type: crate::secret_injection::CredentialType::ApiKey,
        value: "task-presend-secret-31b0".to_string(),
        inject_as: crate::secret_injection::InjectTarget::Query,
        inject_key: "api_key".to_string(),
        tools: vec!["*".to_string()],
    }
}

/// Register `mock` under `name` behind a backend whose send refuses every call.
fn register_refusing(state: &Arc<AppState>, name: &str, mock: &Arc<MockBackend>) {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            enabled: true,
            secrets: vec![query_rule()],
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(mock) as Arc<dyn Transport>);
    assert!(state.backends.register(backend), "'{name}' registers");
}

/// The task's settled row, read from the store.
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

/// R3: a single task call refused in its send settles on the gateway's own
/// answer: the row names the gateway as its author and holds no backend
/// output.
#[tokio::test]
async fn a_task_call_refused_in_its_send_settles_as_the_gateways_answer() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = fixture_state(&two_principal_auth()).await;
    register_refusing(&state, BACKEND, &mock);
    let created = post(&state, "key-a", task_invoke(1, "refused-send", json!({}))).await;
    let row = settled_row(&state, &task_id(&created)).await;
    std::assert_eq!(mock.calls(), 0, "premise: nothing sent");
    std::assert_eq!(
        row.error_author,
        Some(crate::gateway::task_service::ErrorAuthor::Gateway),
        "the refusal in the send was stored as the backend's answer"
    );
    assert!(
        row.backend_result().is_none() && row.backend_error().is_none(),
        "the gateway's answer is not backend output"
    );
}

/// R2: a plan whose second step is refused in its send: the refused step is
/// never a relay replay call; alpha's step, which ran, is.
#[tokio::test]
async fn a_plan_step_refused_in_its_send_is_no_replay_call() {
    use super::relay_plan_replay::{
        ALPHA, BETA, OTHER_PROSE, PROSE, playbook, playbook_args, rig, task_call,
    };
    let rig = rig(PROSE, OTHER_PROSE, Some(&playbook())).await;
    assert!(
        rig.state.backends.remove(BETA),
        "premise: beta was registered"
    );
    register_refusing(&rig.state, BETA, &rig.beta);
    let created = post(
        &rig.state,
        "key-a",
        task_call(
            1,
            "refused-send-plan",
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
        "the step refused in its send is a replay call"
    );
}
