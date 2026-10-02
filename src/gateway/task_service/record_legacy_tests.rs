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
