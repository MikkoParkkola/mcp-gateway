// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.PARENT.6 test 12: a completed-task retry returns the stored
//! envelope, and its retained result is delivered as `private`.

use super::{BeginOutcome, CommittedTask, RequestId, Task};
use serde_json::json;

#[test]
fn a_retry_that_finds_a_completed_task_delivers_its_result_private() {
    let mut task = Task::create("probe");
    task.complete(json!({"content": [], "cacheScope": "public"}));
    let stored = CommittedTask {
        task,
        revision: 3,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
    };

    let response = BeginOutcome::Existing(stored).into_response(RequestId::Number(9));

    let wire = serde_json::to_value(&response).expect("a response serializes");
    assert_eq!(wire["result"]["resultType"], "task", "{wire}");
    assert_eq!(wire["result"]["status"], "completed", "{wire}");
    assert_eq!(wire["result"]["result"]["cacheScope"], "private", "{wire}");
}

/// `MIK-8052` (operator rule, ideal UX): a sealed task start tells the caller
/// what happened and that it clears, and never a server path.
#[test]
fn a_sealed_start_says_what_happened_without_a_path() {
    let response = BeginOutcome::Sealed.into_response(RequestId::Number(1));
    let error = response.error.expect("a refusal");
    // The code the synchronous path and the upgrade notes give a sealed call.
    assert_eq!(error.code, 409, "{}", error.message);
    assert!(error.message.contains("paused"), "{}", error.message);
    assert!(
        error.message.contains("resume on their own"),
        "{}",
        error.message
    );
    assert!(
        !error.message.contains(".json"),
        "no file is named: {}",
        error.message
    );
}
