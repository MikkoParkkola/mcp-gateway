// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 row 7 (ORACLE.3, test plan r2.1): under `FailClosed`, a
//! grant-withheld surfaced personal capability answers exactly as the same
//! name where it is not surfaced, even when the identity-grant decision the
//! withheld path writes fails to append. The failure is logged, never
//! answered. RED on base (the failed record answers -32005).

use serde_json::{Value, json};

use std::sync::Arc;

use super::MetaMcp;
use super::grant_audit_fixture::{
    CAPS, DECISION_KIND, Endpoint, PERSONAL, capability_backend, decisions, grant, grants, logger,
};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::protocol::RequestId;
use crate::security::audit::AuditFailurePolicy;

/// The capability's owner, granted on the control.
const ALICE: (&str, &str) = ("api_key", "alice");

fn surfaced(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: CAPS.to_string(),
        tool: PERSONAL.to_string(),
    }])
}

/// An ungranted gateway logging to `dir` under `FailClosed`, with its log.
fn denied_gateway(
    endpoint: &Endpoint,
    dir: &tempfile::TempDir,
) -> (MetaMcp, Arc<crate::security::TransparencyLogger>) {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()))
        .with_identity_grants(grants(vec![]));
    meta.enable_transparency_log(Arc::clone(&log));
    meta.set_capabilities(capability_backend(endpoint.port, ALICE));
    (meta, log)
}

async fn call(meta: &MetaMcp) -> Value {
    let who = api_key("alice");
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        PERSONAL,
        json!({}),
        Some("wh-7"),
        context(&who),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serialises")
}

#[test]
fn row7_failed_grant_record_on_a_withheld_name_answers_as_absent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        // Premise: the denied caller's fresh call reaches nothing; the
        // granted control's succeeds.
        let endpoint = Endpoint::start(false).await;
        let control = surfaced(gateway(
            &endpoint,
            vec![grant("g1", ALICE, ALICE)],
            None,
            AuditFailurePolicy::FailClosed,
        ));
        let allowed = call(&control).await;
        assert!(
            allowed.get("error").is_none() && endpoint.arrivals() == 1,
            "premise: the granted control did not succeed: {allowed}"
        );
        let probe_dir = tempfile::tempdir().unwrap();
        let probe = surfaced(gateway(
            &endpoint,
            vec![],
            Some(&probe_dir),
            AuditFailurePolicy::FailClosed,
        ));
        let refused = call(&probe).await;
        assert_eq!(
            endpoint.arrivals(),
            1,
            "premise: withheld reached the endpoint: {refused}"
        );
    });
    let dir = tempfile::tempdir().unwrap();
    let absent_dir = tempfile::tempdir().unwrap();
    let endpoint = runtime.block_on(Endpoint::start(false));
    let (withheld, log) = denied_gateway(&endpoint, &dir);
    let withheld = surfaced(withheld);
    let absent = denied_gateway(&endpoint, &absent_dir).0;
    log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let (answered, warnings) =
        crate::test_log_capture::capture_warnings(|| runtime.block_on(call(&withheld)));
    let expected = runtime.block_on(call(&absent));
    assert_eq!(
        answered, expected,
        "row 7: withheld {answered} vs absent {expected}"
    );
    assert!(
        warnings.contains(super::grant_audit::WITHHELD_RECORD_FAILED),
        "row 7: the failed decision write was not logged as documented:\n{warnings}"
    );
    // The fault was consumed by the withheld call: the next append of the
    // same kind succeeds.
    runtime.block_on(call(&withheld));
    assert_eq!(
        decisions(&dir).len(),
        1,
        "row 7: the next decision record did not append"
    );
    assert_eq!(
        endpoint.arrivals(),
        0,
        "row 7: the withheld call reached the endpoint"
    );
}

/// MIK-8340 row 7b (A5.1): the best-effort write covers the withheld call's
/// own decision only. In one grant slot (one request), a decision noted
/// before the withheld record, whose request-end write fails under
/// `FailClosed`, still answers -32005; the withheld record was written at
/// once. Catches a `note_withheld_best_effort` that takes every note in the slot.
#[tokio::test]
async fn row7b_another_decision_in_the_request_still_fails_closed() {
    let endpoint = Endpoint::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (meta, log) = denied_gateway(&endpoint, &dir);
    let meta = surfaced(meta);
    let who = api_key("bob");
    let caller = context(&who);
    let (own_written, verdict, _) =
        super::grant_audit::with_grant_slot(meta.transparency_logger.as_ref(), async {
            // Another decision in the same request, noted first.
            let other = meta.identity_grant_rule(
                CAPS,
                PERSONAL,
                caller.scope(),
                crate::gateway::authz::Emit::Audit,
            );
            assert!(other.is_err(), "premise: bob holds no grant");
            super::grant_audit::note_withheld_best_effort(CAPS, || {
                meta.withheld_surfaced(CAPS, PERSONAL, &caller, None)
            })
            .await;
            let written_at_once = decisions(&dir).len();
            // Fail the request-end write, which holds only the other one.
            log.fail_next_append_of_kind_for_test(DECISION_KIND);
            written_at_once
        })
        .await;
    assert_eq!(
        own_written, 1,
        "row 7b: the withheld record was not written at once"
    );
    assert!(
        matches!(verdict, Err(crate::Error::AuditUnavailable)),
        "row 7b: the other decision's failed write no longer fails closed: {verdict:?}"
    );
}

/// MIK-8340 row 7c (gpt seat): a withheld call cancelled through
/// `record_withheld` while its own grant record is being written still logs
/// the documented warning when that write fails, because the writing task
/// logs it, not the caller. Waits on the record itself, bounded.
#[test]
fn row7c_a_cancelled_withheld_call_still_logs_its_failed_record() {
    use super::grant_audit::seams;
    // The literal, not the constant: the row also runs on the commit before
    // the fix, where the constant does not exist.
    const WARNING: &str = "The audit record of a withheld surfaced call could not be written";
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (_guard, mut seen) = crate::test_log_capture::live_count(WARNING);
    runtime.block_on(async {
        let endpoint = Endpoint::start(false).await;
        let dir = tempfile::tempdir().unwrap();
        let meta = Arc::new(surfaced(denied_gateway(&endpoint, &dir).0));
        let hold = seams::hold_next_write_for_test();
        seams::fail_append_at_for_test(1);
        let shared = Arc::clone(&meta);
        let caller = tokio::spawn(async move {
            let who = api_key("bob");
            let caller = context(&who);
            super::grant_audit::with_grant_slot(shared.transparency_logger.as_ref(), async {
                shared
                    .record_withheld(
                        CAPS,
                        PERSONAL,
                        super::visible::Withholding::Refused,
                        &caller,
                        None,
                    )
                    .await;
            })
            .await
        });
        hold.held().await;
        caller.abort();
        assert!(caller.await.is_err(), "premise: the caller was cancelled");
        hold.release();
        let logged = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            seen.wait_for(|count| *count >= 1),
        )
        .await;
        assert!(
            matches!(logged, Ok(Ok(_))),
            "row 7c: the cancelled call's failed record was not logged within 10 s"
        );
    });
}
