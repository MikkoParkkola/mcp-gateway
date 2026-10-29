// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task-envelope receipt rows: a receipt covers only the slot an envelope
//! delivered, a rewritten or built envelope is read as one, and a stored result
//! receipts only what the backend wrote. Moved from `relay_delivery_tests.rs`
//! for the file-size ceiling.

use super::*;

/// D6.RELAY.3/.9: a `tasks/get` answer is the gateway's task
/// envelope around the stored result. Only the delivered slot is the
/// backend's text: the envelope's `statusMessage` is not receipted.
#[tokio::test]
async fn a_task_envelope_receipts_only_its_delivered_slot() {
    let (meta, firewall) = relay_meta();
    let stored = text_result(PROSE);
    let delivered = json!({
        "taskId": "t-1",
        "status": "completed",
        "statusMessage": OTHER_PROSE,
        "result": stored,
    });
    let shape = AnswerShape::of("tasks/get");
    receipt_after_rebuild_as(&meta, &stored, &delivered, shape).await;
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the slot lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "envelope text was receipted"
    );
}

/// B04b-1 design, task envelope: an envelope with no delivered
/// slot keeps the receipt staged from the stored slot, also when a final
/// check rewrote the envelope in place (as the rebuild does).
#[tokio::test]
async fn a_rewritten_slotless_envelope_keeps_the_stored_receipt() {
    let (meta, firewall) = relay_meta();
    let stored = text_result(PROSE);
    let before = json!({"taskId": "t-1", "status": "working", "statusMessage": OTHER_PROSE});
    let after = json!({"taskId": "t-1", "status": "working", "statusMessage": "[redacted]"});
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &stored);
            let snapshot = meta.relay_snapshot(&before);
            meta.restage_if_changed(snapshot, Some(&after), AnswerShape::of("tasks/get"));
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the stored slot lost its receipt"
    );
}

/// D6.RELAY.3 (impl review): a task-augmented `gateway_invoke`
/// replay answers with the task envelope the gateway built
/// (`BeginOutcome::into_response`), read as one whatever the method's shape:
/// its `statusMessage` is not receipted, the stored result is. A backend
/// answer shaped like an envelope is read whole.
#[tokio::test]
async fn a_built_task_envelope_is_read_as_one() {
    use crate::gateway::task_service::CommittedTask;
    use crate::gateway::task_service::execution::BeginOutcome;
    use crate::protocol::tasks::{Task, TaskTransition};
    let (meta, firewall) = relay_meta();
    let stored = text_result(PROSE);
    let mut task = Task::create("gateway_invoke").expect("the test clock reads after 1970");
    task.transition(
        TaskTransition::StatusMessage(Some(OTHER_PROSE.to_owned())),
        chrono::Utc::now(),
    )
    .expect("a status message");
    task.complete(&stored)
        .expect("a live task takes its outcome");
    let replay = CommittedTask {
        task,
        revision: 1,
        targets: Vec::new(),
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
    };
    let ((), receipts) = meta
        .collecting_staged(async {
            meta.stage_relay_receipt(RelayKey::new("alice", true), ("alpha", "send"), &stored);
            // No sealed question here, so no holds to carry.
            let replay = crate::gateway::meta_mcp::sealed_hold::Held::new(
                replay,
                crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
            );
            let answer = BeginOutcome::Existing(replay).into_response(RequestId::Number(1));
            meta.rebuild_receipt_from_final(
                answer.result.as_ref(),
                GatewayStamps::Legacy,
                AnswerShape::of("gateway_invoke"),
            );
        })
        .await;
    receipts.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the stored result lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "envelope text was receipted"
    );

    // Control: the same members from a backend, with no envelope built.
    let (meta, firewall) = relay_meta();
    let lookalike = json!({
        "taskId": "t-1",
        "status": "completed",
        "statusMessage": OTHER_PROSE,
        "result": text_result(PROSE),
    });
    receipt_after_rebuild_as(&meta, &lookalike, &lookalike, AnswerShape::Literal).await;
    assert!(
        relayed_by_bob(&firewall, OTHER_PROSE),
        "a backend's envelope-shaped answer was narrowed"
    );
}

/// Backend text a test places where the gateway also writes, with bytes
/// other than the gateway's.
const BACKEND_ADVICE: &str = "Field notes from the upland survey: the stone wall along the east \
    boundary needs resetting, the spring by the shepherd's hut runs clear again, and the gate \
    hinge on the lower track was replaced with a galvanised one before the first snow.";

/// `MIK-7993.STORE.1`/`.2`: a `tasks/get` read restores the row's write
/// record before staging. The advice the gateway wrote into the stored
/// result is not receipted; the backend's text is; and a backend member of
/// the same name holding other bytes stays receipted.
#[tokio::test]
async fn a_stored_result_receipts_only_what_the_backend_wrote() {
    use crate::gateway::meta_mcp::invoke::gateway_writes;
    let written = json!({
        "content": [{"type": "text", "text": PROSE}],
        "_cost_warnings": [OTHER_PROSE],
    });
    // The record the worker stored: the gateway wrote `_cost_warnings`.
    let record = gateway_writes::scope(async {
        gateway_writes::note(gateway_writes::Layer::Value, &["_cost_warnings"], &written);
        gateway_writes::recorded()
    })
    .await;
    assert!(!record.is_empty(), "premise: the note was taken");

    let (meta, firewall) = relay_meta();
    let mut stored = stored_task(|task| {
        task.complete(&written)
            .expect("a live task takes its outcome");
    });
    stored.gateway_writes = record.clone();
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "the backend's text lost its receipt"
    );
    assert!(
        !relayed_by_bob(&firewall, OTHER_PROSE),
        "the gateway's own advice was receipted as backend text"
    );

    // STORE.2: the same record over a backend member of that name with
    // other bytes exempts nothing.
    let (meta, firewall) = relay_meta();
    let backend = json!({
        "content": [{"type": "text", "text": PROSE}],
        "_cost_warnings": [BACKEND_ADVICE],
    });
    let mut stored = stored_task(|task| {
        task.complete(&backend)
            .expect("a live task takes its outcome");
    });
    stored.gateway_writes = record;
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_stored_receipt(RelayKey::new("alice", true), None, &stored);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, BACKEND_ADVICE),
        "a backend member the gateway did not write lost its receipt"
    );
}
