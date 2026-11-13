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
        owner_digest: Box::default(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
        vouching: crate::gateway::task_service::Vouching::Vouched,
        replay_snapshot: None,
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
async fn alice_gateway(dir: &std::sync::Arc<tempfile::TempDir>) -> (Endpoint, MetaMcp) {
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
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    assert_eq!(read(&meta, &finished_task()).await, (false, None));
}

#[tokio::test]
async fn a_legacy_row_without_bindings_is_refused_for_provenance() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let stored = CommittedTask {
        bindings_recorded: false,
        replay_snapshot: None,
        ..finished_task()
    };
    assert_eq!(
        read(&meta, &stored).await,
        (true, Some(json!({"kind": "provenance"})))
    );
}

#[tokio::test]
async fn a_row_without_recorded_targets_is_refused_for_provenance() {
    let dir = crate::test_dir_keep::kept_tempdir();
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
    let dir = crate::test_dir_keep::kept_tempdir();
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

/// A result recorded under an account binding the target no longer runs
/// under (it now runs under none): refused as rebound, -32603, for
/// provenance.
#[tokio::test]
async fn a_rebound_result_is_refused_for_provenance() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let stored = CommittedTask {
        bindings: vec![(
            CAPS.to_owned(),
            PERSONAL.to_owned(),
            Some("another-account#fp".to_owned()),
        )],
        ..finished_task()
    };
    let alice = api_key("alice");
    let caller = context(&alice);
    let (answer, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_delivery(&RequestId::Number(1), &stored, None, Some("s"), &caller)
    })
    .await;
    written.expect("the slot's records are written");
    let answer = answer.expect("a rebound result is refused");
    let refused_by = answer
        .refused_by()
        .map(|r| serde_json::to_value(r).expect("RefusedBy serialises"));
    let response = answer.into_response();
    let error = response.error.as_ref().expect("an error answer");
    assert_eq!(error.code, -32603, "the rebound refusal: {error:?}");
    assert!(
        error.message.contains("different account"),
        "rebound, not legacy: {error:?}"
    );
    assert_eq!(refused_by, Some(json!({"kind": "provenance"})));
}

/// Two recorded targets: the first, Alice's granted capability, is admitted;
/// the second, a capability no grant covers, is refused. The answer names
/// the second target's check, the one that refused.
#[tokio::test]
async fn the_refusing_target_of_two_is_the_one_named() {
    const UNGRANTED: &str = "calendar_write_day";
    let dir = crate::test_dir_keep::kept_tempdir();
    let (endpoint, meta) = alice_gateway(&dir).await;
    let base_url = crate::test_fixture_host::fixture_url(endpoint.port);
    let second = crate::capability::parse_capability(&format!(
        "name: {UNGRANTED}\n\
         description: Write one calendar day\n\
         metadata:\n\
         \x20 exposure: personal\n\
         \x20 identity_owner:\n\
         \x20   authority: {}\n\
         \x20   subject: {}\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: {base_url}\n\
         \x20     path: /write\n\
         \x20     method: POST\n",
        ALICE.0, ALICE.1
    ))
    .expect("the second capability parses");
    meta.caller_capabilities()
        .expect("the fixture's capabilities")
        .register_capability(second)
        .expect("the second capability registers");
    let mut stored = finished_task();
    stored.targets.push(Target {
        server: CAPS.to_owned(),
        tool: UNGRANTED.to_owned(),
    });
    assert_eq!(
        read(&meta, &stored).await,
        (true, Some(json!({"kind": "grant"})))
    );
}

/// A repeated task-augmented call judged against a stored task it may not
/// be served (no recorded bindings): its stored-repeat judgement refuses with
/// the provenance pair, which `deliver` hands to the call's delivery record.
#[tokio::test]
async fn a_refused_stored_repeat_carries_its_pair() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (_endpoint, meta) = alice_gateway(&dir).await;
    let stored = CommittedTask {
        bindings_recorded: false,
        replay_snapshot: None,
        ..finished_task()
    };
    let alice = api_key("alice");
    let caller = context(&alice);
    let (answer, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.refuse_stored_repeat(&RequestId::Number(1), &stored, None, Some("s"), &caller)
    })
    .await;
    written.expect("the slot's records are written");
    let pair = answer
        .as_ref()
        .and_then(super::task_replay::StoredAnswer::refused_by)
        .map(|r| serde_json::to_value(r).expect("RefusedBy serialises"));
    assert_eq!(pair, Some(json!({"kind": "provenance"})));
    // Through delivery: the repeated call delivers the answer in its own
    // cell, and that cell's record names the check.
    let answer = answer.expect("a refused repeat");
    let fields = crate::gateway::delivery_facts::scope(async move {
        let _frame = answer.deliver();
        let mut fields = serde_json::Map::new();
        crate::gateway::delivery_facts::record_fields(
            crate::gateway::delivery_facts::snapshot().as_ref(),
            false,
            &mut fields,
        );
        fields
    })
    .await;
    assert_eq!(fields["response_effect"], json!("refused"), "{fields:?}");
    assert_eq!(
        fields["refused_by"],
        json!({"kind": "provenance"}),
        "{fields:?}"
    );
}
