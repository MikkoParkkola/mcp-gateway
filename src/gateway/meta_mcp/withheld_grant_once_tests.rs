// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7654 (#2447): a direct-name call of a surfaced tool the caller may not
//! invoke records the grant decision that refused it, from one evaluation. A
//! grant reload landing between two evaluations must not leave a record that
//! names a decision other than the refusal served.

use serde_json::json;

use super::super::grant_audit::with_grant_slot;
use super::super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, decisions, grant, grants};
use super::super::grant_decision_audit_tests::{api_key, context, gateway};
use super::after_grant_evaluation;
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("api_key", "alice");

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
    after_grant_evaluation::set(move || {
        *store.write() = grants(vec![grant("g-alice", ALICE, ALICE)]);
    });
    let who = api_key("alice");
    let caller = context(&who);
    let (refusal, written) = with_grant_slot(meta.transparency_logger.as_ref(), async {
        meta.withheld_surfaced(CAPS, PERSONAL, &caller, None)
    })
    .await;
    written.expect("the slot's records are written");
    let refusal = refusal.expect("alice held no grant when the call was judged");
    assert!(refusal.to_string().contains("Unknown tool"), "{refusal}");

    let recorded = decisions(&dir);
    assert_eq!(recorded.len(), 1, "{recorded:#?}");
    assert_eq!(recorded[0]["outcome"], json!("denied"), "{recorded:#?}");
}
