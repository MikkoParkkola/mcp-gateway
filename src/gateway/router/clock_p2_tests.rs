// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T2 and T2b: a task-augmented `tools/call` on a host
//! clock that reads before 1970. A new task needs a `createdAt` it cannot
//! have, so it is refused before any record exists; a task that already
//! exists is answered from its stored handle, which needs no clock.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture, send_with_headers};

const REFUSAL: &str = "task store unavailable";

/// A keyed modern `gateway_invoke` offered as a task on `/mcp`.
async fn task_call(fx: &Fx, key: &str) -> Value {
    let name = "gateway_invoke";
    let params = json!({
        "name": name,
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "task": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            },
            crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
        }
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers)
        .await
        .1
}

/// Rows the task store has committed.
fn stored_tasks(fx: &Fx) -> usize {
    fx.state
        .task_executor
        .service
        .store
        .committed_count_for_test()
}

/// MIK-8202 RECORDER rule (P2 row 2): a NEW task on a clock before 1970 is
/// refused as unavailable, nothing is written, and its key stays unclaimed:
/// the same call on a readable clock creates the task. Mutant: `createdAt`
/// stamped at 1969 (the task is created).
#[tokio::test]
async fn t2_a_new_task_on_an_unreadable_clock_is_refused_and_leaves_its_key_unclaimed() {
    // GIVEN: a gateway that serves tasks, then a clock before 1970
    let fx = fixture(Answer::Ok, |_| {}).await;
    let clock = crate::clock::test_clock::before_epoch();
    // WHEN
    let refused = task_call(&fx, "op-t2").await;
    drop(clock);
    // THEN: refused with the store's answer, nothing on disk
    assert_eq!(refused["error"]["code"], -32603, "{refused}");
    assert_eq!(refused["error"]["message"], REFUSAL, "{refused}");
    assert_eq!(stored_tasks(&fx), 0, "no record was written");
    // AND: the key was never claimed
    let created = task_call(&fx, "op-t2").await;
    assert!(created["result"]["taskId"].is_string(), "{created}");
    assert_eq!(stored_tasks(&fx), 1);
}

/// MIK-8202 (P2 row 2, replay): a task that already exists is answered with
/// its stored handle on a clock before 1970; only a new row needs a date.
/// Mutant: refuse every create on `Err`.
#[tokio::test]
async fn t2b_an_existing_task_on_an_unreadable_clock_replays_its_stored_handle() {
    // GIVEN: a task created on a readable clock
    let fx = fixture(Answer::Ok, |_| {}).await;
    let first = task_call(&fx, "op-t2b").await;
    let task_id = first["result"]["taskId"].clone();
    assert!(task_id.is_string(), "a task was created: {first}");
    // WHEN: the same call on a clock before 1970
    let _clock = crate::clock::test_clock::before_epoch();
    let replay = task_call(&fx, "op-t2b").await;
    // THEN: the stored handle, and no second row
    assert_eq!(replay["result"]["taskId"], task_id, "{replay}");
    assert_eq!(stored_tasks(&fx), 1);
}
