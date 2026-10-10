// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8315 row 5: the stdio task path passes the sync call's authorization
//! before a task or its idempotency key exists. Stdio carries no grant
//! identity, so a personal capability is refused for the sync call and, after
//! the fix, for the task; no grant can turn a stdio resubmit into a success.
use serde_json::{Value, json};

use super::owner2_stdio_tasks::{dispatch, fixture, modern_call};
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, grants,
};

/// A modern `gateway_invoke` of the personal capability, keyed `key`.
fn personal_call(id: u64, key: &str, task: bool) -> Value {
    let mut call = modern_call(id, PERSONAL, key, task);
    call["params"]["arguments"]["server"] = json!(CAPS);
    call
}

#[tokio::test]
async fn a_stdio_task_submit_of_an_ungranted_capability_is_refused_like_the_sync_call() {
    let fixture = Box::pin(fixture(None)).await;
    let endpoint = Endpoint::start(false).await;
    fixture
        .meta
        .set_capabilities(capability_backend(endpoint.port, ("api_key", "alice")));
    fixture.meta.set_identity_grants(grants(vec![]));
    let rows = fixture.tasks.service.store.committed_count_for_test();

    let sync = dispatch(&fixture, personal_call(1, "sa-5-sync", false)).await;
    assert!(
        sync.get("error").is_some(),
        "the sync control is refused: {sync}"
    );
    let task = dispatch(&fixture, personal_call(2, "sa-5", true)).await;

    assert!(
        task.pointer("/result/taskId").is_none(),
        "a task handle was returned for a call the sync path refuses: {task}"
    );
    assert_eq!(
        task.pointer("/error/code"),
        sync.pointer("/error/code"),
        "{task}"
    );
    assert_eq!(
        task.pointer("/error/message"),
        sync.pointer("/error/message"),
        "{task}"
    );
    assert_eq!(fixture.tasks.service.store.committed_count_for_test(), rows);
    assert_eq!(endpoint.arrivals(), 0, "the refused call reached nothing");

    // The refused submit did not keep its key: another request under it is
    // a new task, not a key-reuse conflict.
    let reused = dispatch(&fixture, modern_call(3, "echo", "sa-5", true)).await;
    assert!(
        reused.pointer("/result/taskId").is_some(),
        "the refused submit kept its idempotency key: {reused}"
    );
}
