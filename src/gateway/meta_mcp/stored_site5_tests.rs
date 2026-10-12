// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 T3 (mutant M19): site 5 with an empty target slice.
//!
//! A single-call row reads no target when its creation found no direct job
//! (`execution/worker.rs` `creation_targets`) or when it is an older record
//! with no consistent upstream descriptor (`record.rs` `legacy_targets`).
//! Nothing it names can be proven, so it is served as today.

use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::gateway::meta_mcp::sealed_hold::{CarriedHolds, Held};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::task_service::CommittedTask;
use crate::gateway::task_service::execution::BeginOutcome;
use crate::protocol::RequestId;
use crate::protocol::tasks::Task;

fn stored(task: &Task) -> Held<CommittedTask> {
    Held::new(
        CommittedTask {
            task: task.clone(),
            revision: 2,
            targets: Vec::new(),
            targets_recorded: false,
            output_free: false,
            error_author: None,
            owner_digest: String::new(),
            gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        },
        CarriedHolds::none(),
    )
}

/// T3: a repeat whose stored row names no target is the stored task, exactly
/// as `BeginOutcome::Existing` answers it, and nothing reaches the backend.
/// Refusing an empty slice (M19) answers an error instead.
#[tokio::test]
async fn t3_an_empty_target_slice_serves_the_stored_task() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let mut task = Task::create("gateway_invoke");
    task.complete(serde_json::json!({"content": [{"type": "text", "text": "t3-stored"}]}));
    let id = RequestId::Number(3);
    let served = meta
        .defer_or_serve_existing(id.clone(), "gateway_invoke", &[], stored(&task), &ctx(&AllowAll))
        .await;
    let today = BeginOutcome::Existing(stored(&task)).into_response(id);
    assert_eq!(
        serde_json::to_value(&served).expect("JSON"),
        serde_json::to_value(&today).expect("JSON"),
        "T3: an empty target slice is not served as today"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0, "T3: a call was sent");
}
