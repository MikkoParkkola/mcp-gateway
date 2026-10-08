// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7686: the committed view of a legacy row (before `TARGET_VERSION`)
//! names the one call its own upstream descriptor captured, and nothing else.

use serde_json::json;

use super::{AdmissionRecord, CommittedTask, Record, TARGET_VERSION, Target, UpstreamRecord};
use crate::protocol::tasks::Task;

const DIGEST: &str = "operation-digest";

fn upstream(operation_digest: &str) -> UpstreamRecord {
    UpstreamRecord {
        handle: "peer-task-1".to_owned(),
        backend: "sdk".to_owned(),
        tool: "slow_job".to_owned(),
        arguments: json!({}),
        operation_digest: operation_digest.to_owned(),
    }
}

fn row(task: &Task, version: u32, upstream: Option<UpstreamRecord>) -> Record {
    Record {
        version,
        dispatched: true,
        upstream,
        input_round: None,
        targets: Vec::new(),
        output_free: false,
        error_author: None,
        admission: AdmissionRecord {
            identity_digest: "identity".to_owned(),
            principal_digest: "principal".to_owned(),
            operation_digest: DIGEST.to_owned(),
            representation_digest: "representation".to_owned(),
            metadata_bytes: 0,
        },
        backend: "sdk".to_owned(),
        revision: 1,
        model: task.snapshot(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
    }
}

fn targets(tool: &str, version: u32, upstream: Option<UpstreamRecord>) -> Vec<Target> {
    let task = Task::create(tool);
    let record = row(&task, version, upstream);
    CommittedTask::of(task, &record).targets
}

#[test]
fn a_legacy_row_names_the_call_its_descriptor_captured() {
    assert_eq!(
        targets("gateway_invoke", 3, Some(upstream(DIGEST))),
        vec![Target {
            server: "sdk".to_owned(),
            tool: "slow_job".to_owned(),
        }]
    );
}

#[test]
fn a_legacy_row_without_a_consistent_descriptor_names_nothing() {
    assert!(targets("gateway_invoke", 3, None).is_empty());
    assert!(
        targets("gateway_invoke", 3, Some(upstream("another-operation"))).is_empty(),
        "a descriptor bound to another operation does not speak for this row"
    );
}

/// MIK-7889 (#2620): a row older than the version that introduced `upstream`
/// cannot have captured a descriptor, so one found there (a downgraded or
/// forged row whose digest still matches) names nothing, as store.rs does.
#[test]
fn a_row_older_than_the_descriptor_version_names_nothing() {
    for version in [1, 2] {
        assert!(
            targets("gateway_invoke", version, Some(upstream(DIGEST))).is_empty(),
            "version {version}"
        );
    }
}

#[test]
fn a_legacy_plan_row_names_nothing_even_with_a_descriptor() {
    for plan in ["gateway_execute", "gateway_run_playbook"] {
        assert!(
            targets(plan, 3, Some(upstream(DIGEST))).is_empty(),
            "{plan}"
        );
    }
}

#[test]
fn a_current_row_keeps_its_own_targets() {
    assert!(
        targets("gateway_invoke", TARGET_VERSION, Some(upstream(DIGEST))).is_empty(),
        "a current row's recorded list is authoritative, even when empty"
    );
}

#[test]
fn a_current_row_keeps_recorded_targets_over_its_descriptor() {
    let task = Task::create("gateway_invoke");
    let mut record = row(&task, TARGET_VERSION, Some(upstream(DIGEST)));
    let recorded = Target {
        server: "sdk".to_owned(),
        tool: "recorded_tool".to_owned(),
    };
    record.targets = vec![recorded.clone()];
    assert_eq!(CommittedTask::of(task, &record).targets, vec![recorded]);
}

/// MIK-7116.MIN.2 round 8: a row serves backend output when it holds a
/// result, a backend error or a backend's input requests, unless it holds
/// only the gateway's own failure. Read attribution and the stored-delivery
/// check both key on this one answer.
#[test]
fn a_row_serves_backend_output_by_status() {
    use crate::protocol::JsonRpcError;
    use crate::protocol::mrtr::InputRequired;
    use crate::protocol::tasks::TaskTransition;

    let committed = |task: Task, output_free: bool| CommittedTask {
        task,
        revision: 1,
        targets: Vec::new(),
        targets_recorded: true,
        output_free,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
    };
    let working = Task::create("t");
    let mut completed = working.clone();
    completed.complete(json!({"content": []}));
    let mut failed = working.clone();
    failed.fail(JsonRpcError {
        code: -32000,
        message: "backend".into(),
        data: None,
    });
    let mut asking = working.clone();
    asking
        .transition(
            TaskTransition::RequireInput(InputRequired {
                requests: vec![("q".into(), json!({"method": "roots/list"}))],
                request_state: None,
            }),
            chrono::Utc::now(),
        )
        .expect("a legal round");
    let mut cancelled = working.clone();
    cancelled
        .transition(TaskTransition::Cancel, chrono::Utc::now())
        .expect("a legal cancel");

    assert!(
        !committed(working, false).serves_backend_output(),
        "working"
    );
    assert!(
        !committed(cancelled, false).serves_backend_output(),
        "cancelled"
    );
    assert!(
        committed(completed, false).serves_backend_output(),
        "completed"
    );
    assert!(
        committed(asking, false).serves_backend_output(),
        "input_required"
    );
    assert!(
        committed(failed.clone(), false).serves_backend_output(),
        "failed"
    );
    assert!(
        !committed(failed, true).serves_backend_output(),
        "gateway-only failure"
    );
}

/// A completed row's stored result is backend output, unless it is the
/// gateway's own interrupted or abandoned sentence (or the row is output-free).
#[test]
fn a_gateway_authored_result_is_not_backend_output() {
    use crate::protocol::tasks::TaskTransition;
    let complete = |result: serde_json::Value, output_free: bool| {
        let mut task = Task::create("gateway_invoke");
        task.transition(TaskTransition::Complete(result), chrono::Utc::now())
            .expect("a working task completes");
        let mut record = row(&task, TARGET_VERSION, None);
        record.output_free = output_free;
        CommittedTask::of(task, &record)
    };
    let backend = json!({"content": [{"type": "text", "text": "rows"}], "isError": false});
    assert!(complete(backend.clone(), false).backend_result().is_some());
    assert!(complete(backend, true).backend_result().is_none());
    let own = json!({"content": [], "isError": true,
                     "_meta": {(super::EXECUTION_OUTCOME_KEY): "interrupted"}});
    assert!(complete(own, false).backend_result().is_none());
}

/// The snapshot carries the owner digest the record persisted, so a listener
/// told of a commit needs no later read of a row that may have expired.
#[test]
fn a_committed_snapshot_carries_its_owner_digest() {
    let task = Task::create("probe");
    let record = row(&task, 3, None);
    assert_eq!(CommittedTask::of(task, &record).owner_digest, "principal");
}

/// MIK-7887.RECEIPT.1: the error's author is private record state. It survives
/// a round-trip, is omitted when unset, reads as unset on an older row, and is
/// never part of the task snapshot a `tasks/get` body is built from.
#[test]
fn the_error_author_is_private_record_state() {
    use super::ErrorAuthor;
    let task = Task::create("gateway_invoke");
    let mut record = row(&task, TARGET_VERSION, None);

    let unset = serde_json::to_value(&record).expect("serializes");
    assert!(unset.get("errorAuthor").is_none(), "{unset}");
    let older: Record = serde_json::from_value(unset).expect("an older row loads");
    assert_eq!(older.error_author, None);

    record.error_author = Some(ErrorAuthor::Peer);
    let set = serde_json::to_value(&record).expect("serializes");
    let back: Record = serde_json::from_value(set.clone()).expect("round-trips");
    assert_eq!(back.error_author, Some(ErrorAuthor::Peer));
    assert!(
        set["model"].get("errorAuthor").is_none(),
        "the snapshot carries no author: {set}"
    );
}
