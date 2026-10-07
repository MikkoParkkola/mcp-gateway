// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7798: an agent-JWT listener is re-validated at every delivery, so an
//! agent the registry no longer holds, or holds under another key, receives
//! nothing more and its stream ends with no further frame (design r6: G1, G5,
//! J1). Gateway authentication off, agent authentication on.
//!
//! Every row pairs the refused listener with a live twin that DOES receive, so
//! an absence is about the credential and not a transition never published.
use super::super::super::*;
use super::super::support::*;
use super::agent_task_owner::{AGENT_A, agent_gateway, agent_token, listen_as};
use super::helpers::{
    ARRIVES_WITHIN, EventStream, ReleasedOnDrop, StreamEvent, assert_only_its_own_task,
};

/// The next read on `stream` is its end: no message, not even a graceful one.
async fn assert_ends_unread(stream: &mut EventStream, why: &str) {
    match stream.next(ARRIVES_WITHIN).await {
        StreamEvent::Closed => {}
        StreamEvent::Message(event) => {
            panic!("{why}: its listener must receive nothing and end, yet it carried {event}")
        }
        StreamEvent::Silent => {
            panic!("{why}: its listener must end at the next delivery, yet it stayed open")
        }
    }
}

/// Register `AGENT_A` again under a key its earlier tokens were not signed with.
fn rotate_agent_a(registry: &crate::gateway::oauth::AgentRegistry) {
    registry.register(crate::gateway::oauth::AgentDefinition {
        client_id: AGENT_A.to_string(),
        name: AGENT_A.to_string(),
        hs256_secret: Some("agent-a-rotated-secret-9876543210abcdef".to_string()),
        rs256_public_key: None,
        scopes: vec!["tools:*".to_string()],
        issuer: None,
        audience: Some("task-owner".to_string()),
    });
}

/// R2: agent A leaves the registry while its listener is open. A's next
/// delivery reaches nothing and ends the stream; B, still registered, receives.
#[tokio::test]
async fn a_removed_agents_listener_receives_nothing_and_ends() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let own_a = task_id(&post(&state, &token_a, task_invoke(77981, "removed-a", json!({}))).await);
    gate.0.wait_for_dispatch().await;
    let own_b = task_id(&post(&state, &token_b, task_invoke(77982, "kept-b", json!({}))).await);
    gate.0.wait_for_dispatch().await;
    let mut removed = listen_as(&state, &token_a, 77983, json!({ "taskIds": [&own_a] })).await;
    let mut kept = listen_as(&state, &token_b, 77984, json!({ "taskIds": [&own_b] })).await;

    state
        .agent_auth
        .registry
        .remove(AGENT_A)
        .expect("agent A was registered");
    gate.0.release_all();
    poll_until_terminal(&state, &token_b, &own_b).await;

    assert_only_its_own_task(&mut kept, &own_b, 77984, "the registered agent B").await;
    assert_ends_unread(&mut removed, "agent A was removed from the registry").await;
}

/// R4: agent A is registered again under a new key. A listener holding a
/// token signed with the old key receives nothing and ends; B receives.
#[tokio::test]
async fn a_listener_holding_a_rotated_out_key_receives_nothing_and_ends() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let own_a = task_id(&post(&state, &token_a, task_invoke(77985, "rotated-a", json!({}))).await);
    gate.0.wait_for_dispatch().await;
    let own_b = task_id(&post(&state, &token_b, task_invoke(77986, "kept-b", json!({}))).await);
    gate.0.wait_for_dispatch().await;
    let mut old_key = listen_as(&state, &token_a, 77987, json!({ "taskIds": [&own_a] })).await;
    let mut kept = listen_as(&state, &token_b, 77988, json!({ "taskIds": [&own_b] })).await;

    rotate_agent_a(&state.agent_auth.registry);
    gate.0.release_all();
    poll_until_terminal(&state, &token_b, &own_b).await;

    assert_only_its_own_task(&mut kept, &own_b, 77988, "the registered agent B").await;
    assert_ends_unread(&mut old_key, "agent A's key was rotated").await;
}

/// R14 (listen leg): an embedder mutates the registry mid-stream. A receives
/// while registered; after `remove` its next delivery ends the stream; once
/// registered again with the same key, a NEW listener receives.
#[tokio::test]
async fn an_agent_removed_then_registered_again_is_seen_at_each_delivery() {
    let (mock, gate) = MockBackend::holding(Answer::ok());
    let mut gate = ReleasedOnDrop(gate);
    let (state, _store, token_a, _token_b) = agent_gateway(&mock).await;
    let first = task_id(&post(&state, &token_a, task_invoke(77991, "first-a", json!({}))).await);
    gate.0.wait_for_dispatch().await;
    let second = task_id(&post(&state, &token_a, task_invoke(77992, "second-a", json!({}))).await);
    gate.0.wait_for_dispatch().await;
    let mut stream = listen_as(
        &state,
        &token_a,
        77993,
        json!({ "taskIds": [&first, &second] }),
    )
    .await;

    // Registered: one transition is delivered (whichever task the permit ends).
    gate.0.release();
    let delivered = match stream.next(ARRIVES_WITHIN).await {
        StreamEvent::Message(event) => event,
        StreamEvent::Silent => panic!("a registered agent's transition never arrived"),
        StreamEvent::Closed => panic!("a registered agent's stream ended"),
    };
    let delivered_id = delivered["params"]["taskId"].as_str().unwrap_or_default();
    assert!(
        delivered_id == first || delivered_id == second,
        "the registered agent receives its own transition: {delivered}"
    );

    state
        .agent_auth
        .registry
        .remove(AGENT_A)
        .expect("agent A was registered");
    gate.0.release();
    assert_ends_unread(&mut stream, "agent A was removed after its first delivery").await;

    // Registered again with the same key: a new listener receives.
    let token_again = agent_token(&state.agent_auth.registry, AGENT_A);
    let third = task_id(
        &post(
            &state,
            &token_again,
            task_invoke(77994, "third-a", json!({})),
        )
        .await,
    );
    gate.0.wait_for_dispatch().await;
    let mut fresh = listen_as(&state, &token_again, 77995, json!({ "taskIds": [&third] })).await;
    gate.0.release();
    poll_until_terminal(&state, &token_again, &third).await;
    assert_only_its_own_task(&mut fresh, &third, 77995, "agent A registered again").await;
}
