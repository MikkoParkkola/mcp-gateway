// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The grant decision record's writer fields: the `server` it was asked
//! about, and `invocation_recorded`, whether the call has an invocation
//! record of its own. The marker is read inside the decision's own append.

use std::sync::Arc;

use serde_json::{Value, json};

use super::grant_audit::{in_delivery_scope, with_grant_slot};
use super::grant_audit_fixture::{CAPS, Endpoint, decisions, grant, invocations};
use super::grant_decision_audit_tests::{api_key, call, context, gateway, invoke_args, only};
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
