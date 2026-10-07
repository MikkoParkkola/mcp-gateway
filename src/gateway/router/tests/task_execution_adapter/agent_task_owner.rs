// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8031: with gateway authentication off and agent authentication on,
//! every validated agent's tasks share one owner, so one agent reads, cancels
//! and replays another's task.
//!
//! Each agent presents a JWT the real `agent_auth_middleware` validates. No
//! `VerifiedIdentity` is injected: the owner under test is the one
//! `route_task_owner` derives when gateway authentication is off. The keyless
//! row is the control: callers with no agent identity still share one pool.
use super::super::super::*;
use super::super::support::*;
use super::helpers::{
    EventStream, ReleasedOnDrop, assert_only_its_own_task, assert_receives_nothing, expect_message,
};

pub(super) const AGENT_A: &str = "agent-a";
pub(super) const AGENT_B: &str = "agent-b";

/// Gateway authentication off, with every other field the suite's own.
fn auth_off() -> AuthConfig {
    AuthConfig {
        enabled: false,
        ..two_principal_auth()
    }
}

/// Register `client_id` in `registry` and return a JWT it validates.
pub(super) fn agent_token(
    registry: &crate::gateway::oauth::AgentRegistry,
    client_id: &str,
) -> String {
    let secret = format!("{client_id}-task-owner-secret-0123456789");
    registry.register(crate::gateway::oauth::AgentDefinition {
        client_id: client_id.to_string(),
        name: client_id.to_string(),
        hs256_secret: Some(secret.clone()),
        rs256_public_key: None,
        scopes: vec!["tools:*".to_string()],
        issuer: None,
        audience: Some("task-owner".to_string()),
    });
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({ "sub": client_id, "exp": now + 3600, "iat": now, "aud": "task-owner" }),
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent token")
}

/// Gateway auth off, agent auth on with two agents; returns their tokens.
pub(super) async fn agent_gateway(
    mock: &Arc<MockBackend>,
) -> (Arc<AppState>, tempfile::TempDir, String, String) {
    let (mut state, store) = fixture_state(&auth_off()).await;
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token_a = agent_token(&registry, AGENT_A);
    let token_b = agent_token(&registry, AGENT_B);
    Arc::get_mut(&mut state)
        .expect("no other state handle")
        .agent_auth = crate::gateway::oauth::AgentAuthState::new(true, registry);
    register(&state, BACKEND, mock);
    (state, store, token_a, token_b)
}

/// The JSON-RPC error code of `body`, or a failure naming the whole body.
fn error_code(body: &Value, what: &str) -> i64 {
    body.pointer("/error/code")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{what} must be refused, got {body}"))
}

#[tokio::test]
async fn an_agent_cannot_read_or_cancel_another_agents_task() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let created = post(&state, &token_a, task_invoke(8301, "own-a", json!({}))).await;
    let id = task_id(&created);

    // Twin first: the owner reads its own task, so a refusal below is about
    // the reader and not a task that was never there.
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
        task_method(8302, "tasks/cancel", json!({ "taskId": id })),
    )
    .await;
    std::assert_eq!(
        error_code(&cancel, "agent B's tasks/cancel on agent A's task"),
        -32602,
        "{cancel}"
    );
    let after = get_task(&state, &token_a, &id).await;
    std::assert_ne!(
        status_of(&after),
        "cancelled",
        "agent B's cancel must not reach agent A's task: {after}"
    );
}

#[tokio::test]
async fn an_agent_cannot_update_another_agents_task_and_its_owner_can_cancel_it() {
    // Held, so the task is still working when its owner cancels it.
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let id = task_id(&post(&state, &token_a, task_invoke(8341, "upd-a", json!({}))).await);
    gate.0.wait_for_dispatch().await;

    let update = |rpc| task_method(rpc, "tasks/update", json!({ "taskId": id }));
    let foreign = post(&state, &token_b, update(8342)).await;
    std::assert_eq!(
        foreign.pointer("/error/message").and_then(Value::as_str),
        Some("no such task"),
        "agent B's tasks/update on agent A's task is answered as absent: {foreign}"
    );
    let own = post(&state, &token_a, update(8343)).await;
    assert!(
        own.get("error").is_none(),
        "agent A updates its own task: {own}"
    );

    let cancel = post(
        &state,
        &token_a,
        task_method(8344, "tasks/cancel", json!({ "taskId": id })),
    )
    .await;
    assert!(
        cancel.get("error").is_none(),
        "agent A cancels its own task: {cancel}"
    );
    std::assert_eq!(
        status_of(&get_task(&state, &token_a, &id).await),
        "cancelled"
    );
}

#[tokio::test]
async fn an_agent_reusing_another_agents_idempotency_key_gets_its_own_task() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let first = task_id(&post(&state, &token_a, task_invoke(8311, "shared-key", json!({}))).await);

    // Twin: the same agent replaying its key is handed the same task.
    let replay = task_id(&post(&state, &token_a, task_invoke(8312, "shared-key", json!({}))).await);
    std::assert_eq!(replay, first, "agent A's replay returns its own task");

    let other = task_id(&post(&state, &token_b, task_invoke(8313, "shared-key", json!({}))).await);
    std::assert_ne!(
        other,
        first,
        "agent B's call under agent A's idempotency key must create B's own task, \
         never hand back A's"
    );
}

/// A listen presenting `bearer`, with its acknowledgement consumed.
pub(super) async fn listen_as(
    state: &Arc<AppState>,
    bearer: &str,
    id: i64,
    params: Value,
) -> EventStream {
    let body = task_method(id, "subscriptions/listen", params);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "subscriptions/listen")
        .header("authorization", format!("Bearer {bearer}"))
        .body(axum::body::Body::from(
            serde_json::to_vec(&body).expect("a fixture body serialises"),
        ))
        .expect("a fixture request builds");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    std::assert_eq!(
        response.status(),
        StatusCode::OK,
        "the listen must be admitted"
    );
    let mut stream = EventStream::from_response(response);
    expect_message(&mut stream, "the acknowledgement that opens the stream").await;
    stream
}

#[tokio::test]
async fn an_agent_listening_for_another_agents_task_receives_nothing() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let id = task_id(&post(&state, &token_a, task_invoke(8321, "listen-a", json!({}))).await);
    gate.0.wait_for_dispatch().await;

    let mut own = listen_as(&state, &token_a, 8322, json!({ "taskIds": [&id] })).await;
    let mut foreign = listen_as(&state, &token_b, 8323, json!({ "taskIds": [&id] })).await;

    gate.0.release_all();
    poll_until_terminal(&state, &token_a, &id).await;

    // Positive first: the transition was published to this generation.
    assert_only_its_own_task(&mut own, &id, 8322, "agent A's own stream").await;
    assert_receives_nothing(
        &mut foreign,
        "agent B named agent A's task, which B does not own",
    )
    .await;
}

#[tokio::test]
async fn keyless_callers_on_an_auth_off_gateway_still_share_one_pool() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = fixture_state(&auth_off()).await;
    register(&state, BACKEND, &mock);
    let id = task_id(&post(&state, "anyone-1", task_invoke(8331, "pooled", json!({}))).await);

    let other = get_task(&state, "anyone-2", &id).await;
    assert!(
        !status_of(&other).is_empty(),
        "with no identity at all, callers share the auth-off pool: {other}"
    );
}
