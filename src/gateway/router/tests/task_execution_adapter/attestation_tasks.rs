// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.ATTEST.1 part 3 (b): a surfaced tool run as a task carries the
//! `_meta` attestation token of the request that created it into the worker's
//! dispatch, where the funnel re-validates it. Enforce is built from an env
//! file through the overlay, never hand-built.
use super::super::*;
use super::support::*;
use pretty_assertions::assert_eq;

use crate::attestation::{BnautAttestationSigner, TokenRequest};
use crate::protocol::mrtr::ATTESTATION_META;

const KEY: &str = "surfaced-task-attestation-key-32b";
const KEY_ID: &str = "surfaced-task";

/// The standard suite state with `TOOL` surfaced from [`BACKEND`] and
/// attestation in enforce mode, read from an env file.
async fn surfaced_enforced(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = state_with(mock).await;
    // Warm the catalogue: a surfaced tool the gateway has never listed is
    // confirmed as unclassified before attestation is consulted, and these
    // rows are about attestation. `tools/list` is not counted as a call.
    let backend = state
        .backends
        .get(BACKEND)
        .expect("fixture backend is registered");
    backend
        .get_tools_shared()
        .await
        .expect("the mock serves tools/list");
    let listed = backend
        .get_cached_tool(TOOL)
        .expect("premise: the surfaced tool is in the catalogue");
    assert_ne!(
        listed.annotations.and_then(|a| a.destructive_hint),
        Some(true),
        "premise: the surfaced tool is not destructive, so confirmation stays out of these rows"
    );
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    let (validator, mode) = crate::attestation::wiring::enforce_from_env_file(KEY, KEY_ID);
    app.meta_mcp = Arc::new(
        meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }])
        .with_attestation(validator, mode),
    );
    (Arc::new(app), store)
}

fn token(ttl: chrono::TimeDelta) -> String {
    BnautAttestationSigner::new(KEY.as_bytes().to_vec(), KEY_ID)
        .with_audience("test-gateway")
        .issue(
            &TokenRequest {
                agent_identity: "alice".to_string(),
                task_uuid: uuid::Uuid::new_v4(),
                capabilities: vec![TOOL.to_string()],
            },
            chrono::Utc::now(),
            ttl,
        )
        .encoded()
        .to_string()
}

/// One `tasks/get`, presenting `token` as the recovery attestation if given.
async fn get_attested(state: &Arc<AppState>, id: &str, token: Option<String>) -> Value {
    let mut body = task_method(821, "tasks/get", json!({ "taskId": id }));
    if let Some(token) = token {
        body["params"]["_meta"][crate::gateway::meta_mcp::upstream::RECOVERY_META] =
            json!({ "attestation": token });
    }
    post(state, "key-a", body).await
}

/// `poll_until_terminal` for an enforcing gateway: a finished task is only
/// delivered to a read that presents a fresh recovery token.
async fn poll_attested(state: &Arc<AppState>, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        let body = get_attested(
            state,
            id,
            Some(token(crate::duration_bound::delta!(minutes, 5))),
        )
        .await;
        if is_terminal(&status_of(&body)) {
            return body;
        }
        tokio::task::yield_now().await;
    }
    panic!("task {id} never reached a terminal status");
}

/// A task-augmented call of the surfaced tool by its own name.
fn surfaced_task(id: i64, key: &str, attestation: Option<&str>) -> Value {
    let mut body = keyed(
        modern(
            id,
            "tools/call",
            json!({ "name": TOOL, "arguments": { "q": "surfaced" }, "task": {} }),
            true,
        ),
        key,
    );
    if let Some(token) = attestation {
        body["params"]["_meta"][ATTESTATION_META] = json!(token);
    }
    body
}

/// The refusal, wherever it lands: at creation, or as the task's failure.
async fn refusal_code(state: &Arc<AppState>, created: &Value) -> Option<i64> {
    if let Some(code) = created.pointer("/error/code").and_then(Value::as_i64) {
        return Some(code);
    }
    let id = task_id(created);
    let settled = poll_attested(state, &id).await;
    settled
        .pointer("/result/error/code")
        .and_then(Value::as_i64)
}

#[tokio::test]
async fn surfaced_task_enforce_carries_meta_token() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_enforced(&mock).await;

    // Without a token the task is refused and never reaches the backend.
    let created = post(
        &state,
        "key-a",
        surfaced_task(801, "surfaced-no-token", None),
    )
    .await;
    assert_eq!(
        refusal_code(&state, &created).await,
        Some(-32002),
        "{created}"
    );
    assert_eq!(mock.calls(), 0, "an unattested task must not dispatch");

    // With a valid token it runs once, and the backend never sees the token.
    let valid = token(crate::duration_bound::delta!(minutes, 5));
    let created = post(
        &state,
        "key-a",
        surfaced_task(802, "surfaced-token", Some(&valid)),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_attested(&state, &id).await;
    assert_eq!(status_of(&settled), "completed", "{settled}");
    assert_eq!(mock.calls(), 1, "one attested task, one dispatch");
    for params in mock.seen() {
        let text = params.to_string();
        assert!(
            !text.contains(&valid),
            "the backend received the token: {text}"
        );
        assert!(
            !text.contains(ATTESTATION_META),
            "the backend received the key: {text}"
        );
    }
}

/// A surfaced task whose token expires while it is held before dispatch
/// fails -32002: the carried token is re-validated at dispatch, not only at
/// create, and the backend is never called.
#[tokio::test]
async fn surfaced_task_enforce_rechecks_token_at_dispatch() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_enforced(&mock).await;
    let (observer, mut hold) = observe_dispatched(&state);
    let short = token(crate::duration_bound::delta!(seconds, 2));
    let created = post(
        &state,
        "key-a",
        surfaced_task(803, "surfaced-expiring", Some(&short)),
    )
    .await;
    let id = task_id(&created);
    tokio::time::timeout(std::time::Duration::from_secs(10), hold.arrived.recv())
        .await
        .expect("the worker reaches Dispatched in time")
        .expect("the worker reaches Dispatched");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    hold.disarm_and_release(&observer);
    let settled = poll_attested(&state, &id).await;
    assert_eq!(status_of(&settled), "failed", "{settled}");
    assert_eq!(
        settled
            .pointer("/result/error/code")
            .and_then(Value::as_i64),
        Some(-32002),
        "{settled}"
    );
    assert_eq!(mock.calls(), 0, "the expired task must not dispatch");
}

/// A finished task is read with the same recovery token a working one needs.
#[tokio::test]
async fn a_finished_task_read_needs_a_valid_recovery_token_under_enforce() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = surfaced_enforced(&mock).await;
    let created = post(
        &state,
        "key-a",
        surfaced_task(
            820,
            "fin-att",
            Some(&token(crate::duration_bound::delta!(minutes, 5))),
        ),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_attested(&state, &id).await;
    assert_eq!(status_of(&settled), "completed", "{settled}");
    let bare = get_attested(&state, &id, None).await;
    assert_eq!(bare.pointer("/error/code"), Some(&json!(-32002)), "{bare}");
    assert!(bare.get("result").is_none(), "{bare}");
}
