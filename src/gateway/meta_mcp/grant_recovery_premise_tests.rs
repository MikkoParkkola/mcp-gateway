// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The premise the recovery read relies on: no identity grant can refuse it,
//! because a capability call never offers its reply to an armed upstream
//! submission, so a capability task never holds an upstream handle. The
//! recovery read in `router/handlers/tasks.rs` carries a comment saying so.

use std::sync::Arc;

use serde_json::json;

use super::grant_audit_fixture::{CAPS, Endpoint, PERSONAL, grant, wait_for_decisions};
use super::grant_decision_audit_tests::{api_key, call, gateway, invoke_args};
use super::upstream::{UpstreamSubmission, with_upstream_submission};
use crate::security::audit::AuditFailurePolicy;

/// A capability whose endpoint answers with an upstream task envelope still
/// yields no handle for an armed submission: revisit the recovery read in
/// `router/handlers/tasks.rs` (it assumes a grant can never refuse it) if this
/// row goes red.
#[tokio::test]
async fn a_capability_call_never_offers_an_armed_submission_a_handle() {
    let (endpoint, dir) = (
        Endpoint::start_with_body(json!({
            "resultType": "task", "taskId": "peer-task-1", "status": "working"
        }))
        .await,
        Arc::new(tempfile::tempdir().unwrap()),
    );
    let alice = ("api_key", "alice");
    let meta = gateway(
        &endpoint,
        vec![grant("g1", alice, alice)],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    let submission = Arc::new(UpstreamSubmission::armed_for(CAPS, PERSONAL, "task-1"));

    let answer = with_upstream_submission(
        Arc::clone(&submission),
        call(&meta, &api_key("alice"), "gateway_invoke", invoke_args()),
    )
    .await;

    assert!(
        answer.get("error").is_none(),
        "premise: the call ran: {answer}"
    );
    assert_eq!(endpoint.arrivals(), 1, "premise: the endpoint was reached");
    assert_eq!(submission.handle(), None, "a capability task held a handle");
    let _ = wait_for_decisions(&dir, 1).await;
}
