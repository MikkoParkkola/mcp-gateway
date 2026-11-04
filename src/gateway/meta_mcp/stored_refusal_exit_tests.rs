// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each refused exit of the stored-read judgement names the check that
//! refused it (MIK-9191.RULEID.2, .3): the answer carries the pair its exit
//! returned, and a read that is served carries none.

use serde_json::{Value, json};

use super::MetaMcp;
use super::grant_audit::with_grant_slot;
use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, grant, grants};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::protocol::RequestId;
use crate::security::audit::AuditFailurePolicy;

/// Alice's own capability, granted to her.
const ALICE: (&str, &str) = ("api_key", "alice");

/// A finished task whose one recorded call was Alice's personal capability.
fn finished_task() -> CommittedTask {
    let mut task = Task::create("gateway_invoke").expect("the test clock reads after 1970");
    task.complete(&json!({ "content": [] }))
        .expect("a live task takes its outcome");
    CommittedTask {
        task,
        revision: 1,
        targets: vec![Target {
            server: CAPS.to_owned(),
            tool: PERSONAL.to_owned(),
        }],
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
    }
}

/// One `tasks/get` read as Alice, in a slot as the HTTP handler opens one:
/// whether it was refused, and the refusal its answer carries.
async fn read(meta: &MetaMcp, stored: &CommittedTask) -> (bool, Option<Value>) {
    let alice = api_key("alice");
    let caller = context(&alice);
    let (answer, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_delivery(&RequestId::Number(1), stored, None, Some("s"), &caller)
    })
    .await;
    written.expect("the slot's records are written");
    (
        answer.is_some(),
        answer
            .as_ref()
            .and_then(super::task_replay::StoredAnswer::refused_by)
            .map(|r| serde_json::to_value(r).expect("RefusedBy serialises")),
    )
}

/// Alice's gateway, with the endpoint it serves through: held by the row,
/// so the endpoint lives as long as the gateway.
async fn alice_gateway(dir: &tempfile::TempDir) -> (Endpoint, MetaMcp) {
    let endpoint = Endpoint::start(false).await;
    let meta = gateway(
        &endpoint,
        vec![grant("g-exit", ALICE, ALICE)],
        Some(dir),
        AuditFailurePolicy::FailClosed,
    );
    (endpoint, meta)
}

#[tokio::test]
async fn a_served_read_carries_no_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    assert_eq!(read(&meta, &finished_task()).await, (false, None));
}

#[tokio::test]
async fn a_legacy_row_without_bindings_is_refused_for_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let stored = CommittedTask {
        bindings_recorded: false,
        ..finished_task()
    };
    assert_eq!(
        read(&meta, &stored).await,
        (true, Some(json!({"kind": "provenance"})))
    );
}

#[tokio::test]
async fn a_row_without_recorded_targets_is_refused_for_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let stored = CommittedTask {
        targets: Vec::new(),
        targets_recorded: false,
        ..finished_task()
    };
    assert_eq!(
        read(&meta, &stored).await,
        (true, Some(json!({"kind": "provenance"})))
    );
}

/// A grant revoked after the task finished refuses its reads; a second poll
/// inside the repeat window writes no second grant record, and its answer
/// still names the grant.
#[tokio::test]
async fn a_revoked_grant_is_named_on_every_poll() {
    let dir = tempfile::tempdir().unwrap();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let stored = finished_task();
    meta.set_identity_grants(grants(vec![]));
    for poll in 0..2 {
        assert_eq!(
            read(&meta, &stored).await,
            (true, Some(json!({"kind": "grant"}))),
            "poll {poll}"
        );
    }
}
