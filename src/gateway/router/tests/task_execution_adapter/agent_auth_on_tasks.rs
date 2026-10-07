// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8055: with gateway authentication and agent authentication both on, a
//! validated agent token is a first-class caller on a public `/mcp`: it owns
//! its tasks as its `client_id`, apart from every other agent (design r2: K1,
//! K6). Each row pairs a refusal with the owner's own access, so an absence is
//! about the caller and not a task that never existed.
use super::super::super::*;
use super::super::support::*;
use super::agent_task_owner::{AGENT_A, AGENT_B, agent_token, listen_as};
use super::helpers::{ReleasedOnDrop, assert_only_its_own_task, assert_receives_nothing};

/// Gateway authentication on with `/mcp` public, agent authentication on,
/// agents A and B registered; returns their tokens.
async fn auth_on_agents(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, tempfile::TempDir, String, String) {
    let mut auth = two_principal_auth();
    auth.public_paths = vec!["/mcp".to_string()];
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token_a = agent_token(&registry, AGENT_A);
    let token_b = agent_token(&registry, AGENT_B);
    let (state, store) = agent_fixture_state(
        &auth,
        crate::gateway::oauth::AgentAuthState::new(true, registry),
    )
    .await;
    register(&state, BACKEND, mock);
    (state, store, token_a, token_b)
}

/// The JSON-RPC error code of `body`, or a failure naming the whole body.
fn error_code(body: &Value, what: &str) -> i64 {
    body.pointer("/error/code")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{what} must be refused, got {body}"))
}

/// N1: agent A creates a task and reads it through to its result.
#[tokio::test]
async fn an_agent_creates_and_reads_its_own_task_with_gateway_auth_on() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, _) = auth_on_agents(&mock).await;
    let created = post(&state, &token_a, task_invoke(80551, "n1-a", json!({}))).await;
    assert!(
        created.get("error").is_none(),
        "agent A's task creation must be admitted: {created}"
    );
    let id = task_id(&created);
    let done = poll_until_terminal(&state, &token_a, &id).await;
    std::assert_eq!(status_of(&done), "completed", "{done}");
}

/// N2: agent B can neither read nor cancel agent A's task; A can read it.
#[tokio::test]
async fn an_agent_cannot_reach_another_agents_task_with_gateway_auth_on() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, token_b) = auth_on_agents(&mock).await;
    let created = post(&state, &token_a, task_invoke(80552, "n2-a", json!({}))).await;
    assert!(created.get("error").is_none(), "{created}");
    let id = task_id(&created);
    let own = get_task(&state, &token_a, &id).await;
    assert!(
        !status_of(&own).is_empty(),
        "agent A reads its own task: {own}"
    );

    let foreign = get_task(&state, &token_b, &id).await;
    std::assert_eq!(
        error_code(&foreign, "agent B's tasks/get on agent A's task"),
        -32602,
        "{foreign}"
    );
    let cancel = post(
        &state,
        &token_b,
        task_method(80553, "tasks/cancel", json!({ "taskId": id })),
    )
    .await;
    std::assert_eq!(
        error_code(&cancel, "agent B's tasks/cancel on agent A's task"),
        -32602,
        "{cancel}"
    );
}

/// N3: A's listen for its own task receives its transition; B's listen
/// naming A's task receives nothing.
#[tokio::test]
async fn an_agents_listen_carries_only_its_own_task_with_gateway_auth_on() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store, token_a, token_b) = auth_on_agents(&mock).await;
    let created = post(&state, &token_a, task_invoke(80554, "n3-a", json!({}))).await;
    assert!(created.get("error").is_none(), "{created}");
    let own = task_id(&created);
    gate.0.wait_for_dispatch().await;
    let mut a = listen_as(&state, &token_a, 80555, json!({ "taskIds": [&own] })).await;
    let mut b = listen_as(&state, &token_b, 80556, json!({ "taskIds": [&own] })).await;

    gate.0.release_all();
    poll_until_terminal(&state, &token_a, &own).await;

    assert_only_its_own_task(&mut a, &own, 80555, "agent A, the owner").await;
    assert_receives_nothing(&mut b, "agent B named agent A's task").await;
}

/// N6: A replaying its idempotency key gets its own task back; B reusing the
/// same key gets a task of its own, never A's.
#[tokio::test]
async fn idempotency_keys_stay_per_agent_with_gateway_auth_on() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, token_b) = auth_on_agents(&mock).await;
    let first = post(&state, &token_a, task_invoke(80557, "n6-key", json!({}))).await;
    assert!(first.get("error").is_none(), "{first}");
    let first = task_id(&first);
    let replay = task_id(&post(&state, &token_a, task_invoke(80558, "n6-key", json!({}))).await);
    std::assert_eq!(replay, first, "agent A's replay returns its own task");
    let other = task_id(&post(&state, &token_b, task_invoke(80559, "n6-key", json!({}))).await);
    std::assert_ne!(other, first, "agent B never gets agent A's task back");
}

/// `events/subscribe` for an event no catalogue holds, as `bearer`, on
/// `state` with an events hub installed.
async fn subscribe_unknown(
    state: &Arc<AppState>,
    bearer: &str,
    store: &tempfile::TempDir,
) -> Value {
    let hub = crate::events::EventsHub::open(
        &crate::config::EventsConfig::default(),
        &store.path().join("events"),
    )
    .expect("the events hub opens");
    state.meta_mcp.set_events(hub);
    post(
        state,
        bearer,
        task_method(
            80560,
            "events/subscribe",
            json!({ "name": "no.such.event", "delivery": { "mode": "webhook", "url": "https://hooks.example/n8" } }),
        ),
    )
    .await
}

/// N8 (K6): an agent-only caller still has no events principal, so its
/// `events/subscribe` is refused at the principal gate (`-32012`). Twin: a
/// gateway key caller with the same params passes that gate and is refused
/// later, for the unknown event (`-32011`), so the agent's refusal is the
/// principal and not the params.
#[tokio::test]
async fn an_agent_only_caller_has_no_events_principal() {
    let mock = MockBackend::answering(Answer::ok());
    let (agents, agents_store, token_a, _) = auth_on_agents(&mock).await;
    let agent = subscribe_unknown(&agents, &token_a, &agents_store).await;
    std::assert_eq!(
        error_code(&agent, "the agent-only subscribe"),
        -32012,
        "{agent}"
    );

    let (keyed, keyed_store) = fixture_state(&two_principal_auth()).await;
    let key = subscribe_unknown(&keyed, "key-a", &keyed_store).await;
    std::assert_eq!(
        error_code(&key, "the key caller's subscribe"),
        -32011,
        "{key}"
    );
}
