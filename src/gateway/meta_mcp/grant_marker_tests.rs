// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The grant decision record's writer fields: the `server` it was asked
//! about, and `invocation_recorded`, whether the call has an invocation
//! record of its own. The marker is read inside the decision's own append.

use std::sync::Arc;

use serde_json::{Value, json};

use super::grant_audit::{in_delivery_scope, with_grant_slot};
use super::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, decisions, entries, grant, invocations, wait_for_decisions,
};
use super::grant_decision_audit_tests::{api_key, call, context, gateway, invoke_args, only};
use super::visible::Withholding;
use crate::gateway::authz::Emit;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");

/// One decision written by a bare check in a slot, run by `check`.
async fn bare_check_record(
    check: impl FnOnce(&super::MetaMcp, &super::MetaMcpCallerContext<'_>),
) -> Value {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);
    let who = api_key("alice");
    let caller = context(&who);
    let ((), written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        check(&meta, &caller);
    })
    .await;
    written.expect("the slot's records are written");
    assert!(
        invocations(&dir).is_empty(),
        "premise: the call wrote an invocation record"
    );
    only(decisions(&dir), "decision record")
}

#[tokio::test]
async fn a_decision_noted_after_the_invocation_record_landed_says_recorded() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::BestEffort);

    let answer = call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;

    assert!(answer.get("error").is_none(), "{answer}");
    only(invocations(&dir), "invocation record");
    let record = only(decisions(&dir), "decision record");
    assert_eq!(record["invocation_recorded"], json!(true), "{record}");
}

#[tokio::test]
async fn a_decision_in_a_slot_whose_call_wrote_no_invocation_says_not_recorded() {
    let record = bare_check_record(|meta, caller| {
        meta.check_invocation_policy(&invoke_args(), Some("d6"), caller)
            .expect("the grant allows the check");
    })
    .await;

    assert_eq!(record["invocation_recorded"], json!(false), "{record}");
}

#[tokio::test]
async fn a_decision_noted_inside_a_delivery_scope_says_recorded() {
    let record = bare_check_record(|meta, caller| {
        in_delivery_scope(|| meta.check_invocation_policy(&invoke_args(), Some("d6"), caller))
            .expect("the grant allows the check");
    })
    .await;

    assert_eq!(record["invocation_recorded"], json!(true), "{record}");
}

#[tokio::test]
async fn every_decision_names_the_server_it_was_asked_about() {
    let record = bare_check_record(|meta, caller| {
        meta.check_invocation_policy(&invoke_args(), Some("d6"), caller)
            .expect("the grant allows the check");
    })
    .await;

    assert_eq!(record["server"], json!(CAPS), "{record}");
}

/// An ungranted gateway logging to `dir` under `policy`: a call through
/// `gateway_invoke` is refused at the gate, with its own invocation record.
async fn refused_call(
    dir: &Arc<tempfile::TempDir>,
    policy: AuditFailurePolicy,
    fail_invocation_append: bool,
) -> Value {
    let endpoint = Endpoint::start(false).await;
    let meta = gateway(&endpoint, vec![], Some(dir), policy);
    if fail_invocation_append {
        let log = meta.transparency_logger.as_ref().expect("the gateway logs");
        // The invocation record's route; the decision record has none.
        log.fail_next_append_of_kind_for_test("meta");
    }
    call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await
}

#[tokio::test]
async fn a_gate_refused_call_with_its_invocation_record_is_recorded() {
    let dir = Arc::new(tempfile::tempdir().unwrap());

    refused_call(&dir, AuditFailurePolicy::BestEffort, false).await;

    only(invocations(&dir), "invocation record");
    let record = only(wait_for_decisions(&dir, 1).await, "decision record");
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["invocation_recorded"], json!(true), "{record}");
}

#[tokio::test]
async fn a_refusal_whose_invocation_append_failed_is_an_unrecorded_decision() {
    for policy in [
        AuditFailurePolicy::FailClosed,
        AuditFailurePolicy::BestEffort,
    ] {
        let dir = Arc::new(tempfile::tempdir().unwrap());

        refused_call(&dir, policy, true).await;

        let held = entries(&dir);
        assert!(invocations(&dir).is_empty(), "{policy:?}: {held:#?}");
        let record = only(wait_for_decisions(&dir, 1).await, "decision record");
        let marker = &record["invocation_recorded"];
        assert_eq!(marker, &json!(false), "{policy:?}: {record}");
    }
}

#[tokio::test]
async fn a_withheld_note_outside_any_slot_is_written_at_once_unrecorded() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    let who = api_key("alice");
    let _unslotted = super::grant_audit::allow_unslotted_check_for_test();

    meta.record_withheld(CAPS, PERSONAL, Withholding::Refused, &context(&who), None)
        .await;

    let held = wait_for_decisions(&dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}");
    assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
    assert!(
        invocations(&dir).is_empty(),
        "no slot means no invocation record"
    );
}

static DENY: crate::gateway::authz::DenyAll = crate::gateway::authz::DenyAll;

/// The best-effort write of a slotted withheld note is parked at its start
/// (S5): the slot's answer still arrives, so no caller path awaits it, and
/// the slot's own fail-closed note is already written, so the held write
/// cannot have taken the append permit ahead of that flush.
#[tokio::test]
async fn a_blocked_withheld_writer_never_holds_the_slots_answer() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::FailClosed);
    let who = api_key("alice");
    let mut caller = context(&who);
    caller.authorizer = &DENY;
    let hold = super::grant_audit::seams::hold_next_best_effort_write_for_test();

    let slot = with_grant_slot(meta.transparency_logger.as_ref(), async {
        // An ordinary fail-closed note, then the withheld call's own.
        let scope = caller.scope();
        let first = meta.identity_grant_rule(CAPS, PERSONAL, scope, Emit::Audit);
        assert!(first.is_ok(), "premise: alice holds the grant");
        meta.record_withheld(CAPS, PERSONAL, Withholding::Refused, &caller, None)
            .await;
    });
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), slot).await;

    let ((), verdict, _) = answered.expect("the slot waited for its withheld note's writer");
    verdict.expect("a withheld note never changes the answer");
    let flushed = decisions(&dir);
    assert_eq!(flushed.len(), 1, "the fail-closed note first: {flushed:#?}");
    let parked = tokio::time::timeout(std::time::Duration::from_secs(10), hold.held()).await;
    assert!(parked.is_ok(), "the withheld write never reached its hold");
    hold.release();
    let both = wait_for_decisions(&dir, 2).await;
    assert_eq!(both.len(), 2, "each note written once: {both:#?}");
}

/// A finished task's stored delivery is re-checked inside the repeat scope
/// (task reads, notification frames, repeated task-augmented calls): its
/// call already has the original request's invocation record, so a refusal
/// there is a delivery and says so.
#[tokio::test]
async fn a_refused_stored_delivery_recheck_says_recorded() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    let who = api_key("alice");
    let caller = context(&who);
    let store = Arc::new(super::grant_audit::DecisionDedupe::default());

    let ((), written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        let refused = super::grant_audit::in_repeat_scope(&store, "task|caller".into(), || {
            meta.check_invocation_policy(&invoke_args(), Some("d10"), &caller)
        });
        assert!(refused.is_err(), "premise: the revoked grant refuses");
    })
    .await;

    written.expect("the slot's records are written");
    let record = only(decisions(&dir), "decision record");
    assert_eq!(record["outcome"], json!("denied"), "{record}");
    assert_eq!(record["invocation_recorded"], json!(true), "{record}");
}

/// A call cancelled while its invocation append is in the kernel: the append
/// survives the cancellation and lands, and the guard writes the withheld
/// note behind it, so the note says recorded and the call is one row.
// `write_in_flight_for_test` exists only with the firewall feature.
#[cfg(feature = "firewall")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_cancelled_during_its_invocation_append_is_one_recorded_decision() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = Arc::new(gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    ));
    let log = meta.transparency_logger.clone().expect("the gateway logs");
    let gate = log.stall_next_write_for_test(std::time::Duration::from_secs(30));
    let running = tokio::spawn({
        let meta = Arc::clone(&meta);
        async move {
            let who = api_key("alice");
            call(&meta, &who, "gateway_invoke", invoke_args()).await
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !log.write_in_flight_for_test() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(
        log.write_in_flight_for_test(),
        "premise: the append is in flight"
    );

    running.abort();
    let _ = running.await;
    log.release_and_drain(gate).await;

    let held = wait_for_decisions(&dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}");
    assert_eq!(held[0]["invocation_recorded"], json!(true), "{held:#?}");
    assert_eq!(invocations(&dir).len(), 1, "the append survived the cancel");
}

/// An invocation append that outlives its caller's timeout and then lands:
/// the decision, appended after it, reads the landed trace id, so the call
/// is one row. The withheld write is parked until the append has landed.
#[tokio::test]
async fn an_append_that_outlives_its_caller_marks_the_decision_recorded() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    let log = meta.transparency_logger.clone().expect("the gateway logs");
    let gate = log.stall_next_write_for_test(std::time::Duration::from_millis(100));
    let hold = super::grant_audit::seams::hold_next_best_effort_write_for_test();

    let _answered = call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;
    let parked = tokio::time::timeout(std::time::Duration::from_secs(10), hold.held()).await;
    assert!(
        parked.is_ok(),
        "premise: the withheld write reached its hold"
    );
    assert!(
        invocations(&dir).is_empty(),
        "premise: the append is still stuck"
    );
    log.release_and_drain(gate).await;
    hold.release();

    let landed = wait_for_decisions(&dir, 1).await;
    assert_eq!(landed.len(), 1, "{landed:#?}");
    assert_eq!(landed[0]["invocation_recorded"], json!(true), "{landed:#?}");
    assert_eq!(invocations(&dir).len(), 1, "the late append landed");
}

/// A slow upstream: the call's decision is written once, after the call's
/// invocation record, and says so.
#[tokio::test]
async fn a_slow_call_writes_its_decision_once_after_its_invocation_record() {
    let endpoint = Arc::new(Endpoint::start(true).await);
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = Arc::new(gateway(
        &endpoint,
        rows,
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    ));
    let running = tokio::spawn({
        let meta = Arc::clone(&meta);
        async move { call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()).await }
    });
    endpoint.wait_for_arrivals(1).await;
    assert!(
        invocations(&dir).is_empty(),
        "premise: the call is still running"
    );

    endpoint.release();
    let answer = running.await.expect("the call task completes");

    assert!(answer.get("error").is_none(), "{answer}");
    let held = wait_for_decisions(&dir, 1).await;
    assert_eq!(held.len(), 1, "written once: {held:#?}");
    assert_eq!(held[0]["invocation_recorded"], json!(true), "{held:#?}");
    assert_eq!(invocations(&dir).len(), 1, "the call's own record");
}

/// A caller cancelled while the slot's awaited flush is held: the withheld
/// note waits in the slot's best-effort list, and the guard still writes it,
/// once, behind the flush that the cancelled caller left running.
// Current-thread: the hold seam is a thread-local, seen only by tasks on the
// test's own thread.
#[tokio::test]
async fn a_caller_cancelled_during_the_flush_still_gets_its_withheld_note_written() {
    let (endpoint, dir) = (
        Endpoint::start(false).await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let rows = vec![grant("g1", ALICE, ALICE)];
    let meta = Arc::new(gateway(
        &endpoint,
        rows,
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    ));
    let hold = super::grant_audit::seams::hold_next_write_for_test();
    let running = tokio::spawn({
        let meta = Arc::clone(&meta);
        async move {
            let (alice, bob) = (api_key("alice"), api_key("bob"));
            let (owner, other) = (context(&alice), context(&bob));
            with_grant_slot(meta.transparency_logger.as_ref(), async {
                // A fail-closed note for the flush to hold (alice, allowed), then
                // a withheld one (bob, who is not the owner: denied).
                let first = meta.identity_grant_rule(CAPS, PERSONAL, owner.scope(), Emit::Audit);
                assert!(first.is_ok(), "premise: alice holds the grant");
                meta.record_withheld(CAPS, PERSONAL, Withholding::Refused, &other, None)
                    .await;
            })
            .await
        }
    });
    let parked = tokio::time::timeout(std::time::Duration::from_secs(10), hold.held()).await;
    assert!(parked.is_ok(), "premise: the flush is held");

    running.abort();
    let _ = running.await;
    hold.release();

    let both = wait_for_decisions(&dir, 2).await;
    let mut outcomes: Vec<&str> = both
        .iter()
        .map(|d| d["outcome"].as_str().unwrap_or_default())
        .collect();
    outcomes.sort_unstable();
    // The flush's allowed decision and the withheld call's denied one, once each.
    assert_eq!(outcomes, ["denied", "ok"], "{both:#?}");
}
