// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7654 (#2447): a direct-name call of a surfaced tool the caller may not
//! invoke records the grant decision that refused it, from one evaluation. A
//! grant reload landing between two evaluations must not leave a record that
//! names a decision other than the refusal served.

use serde_json::json;

use super::super::grant_audit::{allow_unslotted_check_for_test, with_grant_slot};
use super::super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, decisions, grant, grants};
use super::super::grant_decision_audit_tests::{api_key, context, gateway};
use super::after_grant_evaluation;
use crate::Error;
use crate::gateway::authz::DenyAll;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");
static DENY: DenyAll = DenyAll;

#[tokio::test]
async fn a_reload_after_the_refusal_does_not_change_the_recorded_decision() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    // The owner holds no grant when the call is judged; one is published at
    // once. Only the owner can be granted (a non-owner is refused before any
    // grant is read), so only the owner's call can flip on a reload.
    let store = std::sync::Arc::clone(&meta.identity_grants);
    let fired = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = std::rc::Rc::clone(&fired);
    after_grant_evaluation::set(move || {
        flag.set(true);
        *store.write() = grants(vec![grant("g-alice", ALICE, ALICE)]);
    });
    let who = api_key("alice");
    let caller = context(&who);
    let (refusal, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.withheld_surfaced(CAPS, PERSONAL, &caller, None)
    })
    .await;
    written.expect("the slot's records are written");
    assert!(
        fired.get(),
        "the reload must land after the first evaluation"
    );
    let refusal = refusal.expect("alice held no grant when the call was judged");
    assert!(refusal.to_string().contains("Unknown tool"), "{refusal}");

    let recorded = decisions(&dir);
    assert_eq!(recorded.len(), 1, "{recorded:#?}");
    assert_eq!(recorded[0]["outcome"], json!("denied"), "{recorded:#?}");
}

/// An allowed direct-name call is not withheld and records no decision at
/// this step: the dispatch that follows records its own, once.
#[tokio::test]
async fn an_allowed_call_records_no_decision_at_this_step() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let rows = vec![grant("g-alice", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::FailClosed);
    let who = api_key("alice");
    let caller = context(&who);
    let (refusal, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.withheld_surfaced(CAPS, PERSONAL, &caller, None)
    })
    .await;
    written.expect("the slot's records are written");
    assert!(refusal.is_none(), "{refusal:?}");
    let recorded = decisions(&dir);
    assert_eq!(recorded.len(), 0, "{recorded:#?}");
}

/// A call refused before the grant rule (by the authorizer) is still a
/// dispatch: its grant decision is recorded (D3-a), and the answer is the
/// absent-name one.
#[tokio::test]
async fn a_refusal_before_the_grant_rule_still_records_the_decision() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let rows = vec![grant("g-alice", ALICE, ALICE)];
    let meta = gateway(&endpoint, rows, Some(&dir), AuditFailurePolicy::FailClosed);
    let who = api_key("alice");
    let mut caller = context(&who);
    caller.authorizer = &DENY;
    let (refusal, written, _) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.withheld_surfaced(CAPS, PERSONAL, &caller, None)
    })
    .await;
    written.expect("the slot's records are written");
    let refusal = refusal.expect("the authorizer refuses");
    assert!(refusal.to_string().contains("Unknown tool"), "{refusal}");
    let recorded = decisions(&dir);
    assert_eq!(recorded.len(), 1, "{recorded:#?}");
    // The grant allowed it; the authorizer refused. The record is the grant's.
    assert_eq!(recorded[0]["outcome"], json!("ok"), "{recorded:#?}");
}

/// A refusing decision that cannot be noted (no slot to hold it) answers
/// `AuditUnavailable`, never the absent-name refusal.
#[tokio::test]
async fn an_unnoted_refusal_is_audit_unavailable() {
    let (endpoint, dir) = (Endpoint::start(false).await, tempfile::tempdir().unwrap());
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let who = api_key("alice");
    let caller = context(&who);
    let _allowed = allow_unslotted_check_for_test();
    let refusal = meta.withheld_surfaced(CAPS, PERSONAL, &caller, None);
    assert!(
        matches!(refusal, Some(Error::AuditUnavailable)),
        "{refusal:?}"
    );
}
