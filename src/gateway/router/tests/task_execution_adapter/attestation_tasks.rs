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
    let settled = poll_until_terminal(state, "key-a", &id).await;
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
    let valid = token(chrono::TimeDelta::minutes(5));
    let created = post(
        &state,
        "key-a",
        surfaced_task(802, "surfaced-token", Some(&valid)),
    )
    .await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
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

    // A token that expires while the task is held before dispatch fails the
    // task: the carried token is re-validated at dispatch, not only at create.
    let (observer, mut hold) = observe_dispatched(&state);
    let short = token(chrono::TimeDelta::seconds(2));
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
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_eq!(status_of(&settled), "failed", "{settled}");
    assert_eq!(
        settled
            .pointer("/result/error/code")
            .and_then(Value::as_i64),
        Some(-32002),
        "{settled}"
    );
    assert_eq!(mock.calls(), 1, "the expired task must not dispatch");
}
