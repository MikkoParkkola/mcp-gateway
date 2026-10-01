// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7215.CONTROL.5, G4 on the task path: a task's calls key their hints on
//! the caller key of the request that created or resumed it, so an
//! authenticated caller's task gets its own hints and never another caller's.
//! The A/B arm reads the same key (`MetaMcpCallerContext::experiment_key`).

use super::super::*;
use super::input_round::{STATE_1, answer, ask, done, update, wait_input_required};
use super::support::*;
use crate::gateway::router::tests::g4_caller_keyed::{PROJ_CAPS, PROJ_DAY, projected_capability};
use crate::projection::ProjectionMode;

/// The second backend, so two callers' tool keys differ.
const OTHER: &str = "mock2";

/// Two credentials, both reaching every backend.
fn auth() -> AuthConfig {
    let key = |k: &str, name: &str| crate::config::ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(k.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec![
            BACKEND.to_string(),
            OTHER.to_string(),
            PROJ_CAPS.to_string(),
        ],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    };
    AuthConfig {
        enabled: true,
        api_keys: vec![
            key("key-a", "principal-a"),
            key("key-b", "principal-b"),
            key("key-admin", "principal-admin"),
        ],
        ..AuthConfig::default()
    }
}

async fn state(main: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = fixture_state(&auth()).await;
    register(&state, BACKEND, main);
    register(&state, OTHER, &MockBackend::answering(Answer::ok()));
    state
        .meta_mcp
        .set_transition_tracker(Arc::new(crate::transition::TransitionTracker::new()));
    (state, store)
}

fn task_at(id: i64, key: &str, server: &str) -> Value {
    keyed(
        modern(
            id,
            "tools/call",
            json!({
                "name": "gateway_invoke",
                "arguments": { "server": server, "tool": TOOL, "arguments": { "q": 1 } },
                "task": {}
            }),
            true,
        ),
        key,
    )
}

/// Run one task to its end as `principal` and return the settled task.
async fn run(state: &Arc<AppState>, principal: &str, id: i64, server: &str) -> Value {
    let key = format!("g4-task-{principal}-{id}");
    let created = post(state, principal, task_at(id, &key, server)).await;
    let task = task_id(&created);
    poll_until_terminal(state, principal, &task).await
}

/// The `predicted_next` hints anywhere in a body, as text; JSON carried in a
/// string leaf is parsed too.
fn hints(body: &Value) -> String {
    match body {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                if k == "predicted_next" {
                    v.to_string()
                } else {
                    hints(v)
                }
            })
            .collect(),
        Value::Array(items) => items.iter().map(hints).collect(),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .map(|inner| hints(&inner))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

#[tokio::test]
async fn an_authenticated_task_gets_hints_from_its_own_history() {
    let (state, _store) = state(&MockBackend::answering(Answer::ok())).await;
    for id in 1..=3 {
        run(&state, "key-a", id, BACKEND).await;
    }
    let last = run(&state, "key-a", 4, BACKEND).await;
    assert!(
        hints(&last).contains(&format!("{BACKEND}:{TOOL}")),
        "the task's own history is not predicted: {last}"
    );
}

#[tokio::test]
async fn two_callers_tasks_never_become_each_others_predecessor() {
    let (state, _store) = state(&MockBackend::answering(Answer::ok())).await;
    for round in 0..3 {
        run(&state, "key-a", 10 + round, BACKEND).await;
        run(&state, "key-b", 20 + round, OTHER).await;
    }
    let last = run(&state, "key-a", 30, BACKEND).await;
    let seen = hints(&last);
    assert!(
        seen.contains(&format!("{BACKEND}:{TOOL}")),
        "key-a's own history is not predicted: {last}"
    );
    assert!(
        !seen.contains(OTHER),
        "key-b's task was learned as key-a's successor: {last}"
    );
}

#[tokio::test]
async fn a_resumed_task_keeps_its_callers_hints() {
    // Four plain tasks, then one whose backend asks first and is resumed.
    let mock = MockBackend::answering(Answer::Sequence(vec![
        done(),
        done(),
        done(),
        done(),
        ask("confirm", STATE_1),
        done(),
    ]));
    let (state, _store) = state(&mock).await;
    for id in 1..=4 {
        run(&state, "key-a", id, BACKEND).await;
    }
    let created = post(
        &state,
        "key-a",
        declaring_elicitation(task_at(5, "g4-task-resumed", BACKEND)),
    )
    .await;
    let task = task_id(&created);
    wait_input_required(&state, &task).await;
    let acked = post(
        &state,
        "key-a",
        update(6, &task, json!({ "confirm": answer() })),
    )
    .await;
    assert!(
        acked.get("error").is_none(),
        "the answer is accepted: {acked}"
    );
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert!(
        hints(&settled).contains(&format!("{BACKEND}:{TOOL}")),
        "the resumed call lost its caller's hints: {settled}"
    );
}

/// A task's arm is its caller's: the same shape as that caller's own
/// synchronous call. `key-admin`'s key (verified subject `root`) hashes to
/// treatment offline, so a task that lost the key would get the control shape.
#[tokio::test]
async fn a_tasks_arm_is_its_callers_arm() {
    let endpoint = crate::gateway::meta_mcp::grant_audit_fixture::Endpoint::start(false).await;
    let (state, _store) =
        crate::gateway::router::tests::meta_fixture::test_router_app_state_with_meta(
            &auth(),
            None,
            |meta| meta.with_projection_mode(ProjectionMode::Experimental),
        )
        .await;
    state
        .meta_mcp
        .set_capabilities(projected_capability(endpoint.port));
    let invoke = json!({ "server": PROJ_CAPS, "tool": PROJ_DAY, "arguments": {} });
    let sync = post(
        &state,
        "key-admin",
        modern(
            1,
            "tools/call",
            json!({ "name": "gateway_invoke", "arguments": invoke }),
            true,
        ),
    )
    .await;
    let created = post(
        &state,
        "key-admin",
        keyed(
            modern(
                2,
                "tools/call",
                json!({ "name": "gateway_invoke", "arguments": invoke, "task": {} }),
                true,
            ),
            "g4-task-arm",
        ),
    )
    .await;
    let settled = poll_until_terminal(&state, "key-admin", &task_id(&created)).await;
    assert!(
        sync.to_string().contains("_raw"),
        "the caller is in treatment: {sync}"
    );
    assert!(
        settled.to_string().contains("_raw"),
        "the task's arm is not its caller's: {settled}"
    );
}

/// A resume renews its caller's reclaim deadline, as a direct call does: a
/// task parked past the idle sweep would otherwise write hint state under a
/// key nothing tracks any more.
#[tokio::test]
async fn a_resume_renews_its_callers_reclaim_deadline() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (mut state, _store) = fixture_state(&auth()).await;
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .session_lifecycle = Some(Arc::clone(&lifecycle));
    register(&state, BACKEND, &mock);
    let created = post(
        &state,
        "key-a",
        declaring_elicitation(task_at(1, "g4-task-renew", BACKEND)),
    )
    .await;
    let task = task_id(&created);
    wait_input_required(&state, &task).await;
    // The idle sweep reclaims the key while the task waits for input.
    lifecycle.reap(u64::MAX);
    assert_eq!(lifecycle.tracked_count(), 0, "the sweep reclaimed the key");
    let acked = post(
        &state,
        "key-a",
        update(2, &task, json!({ "confirm": answer() })),
    )
    .await;
    assert!(
        acked.get("error").is_none(),
        "the answer is accepted: {acked}"
    );
    assert_eq!(
        lifecycle.tracked_count(),
        1,
        "the resume did not renew its caller's deadline"
    );
}
