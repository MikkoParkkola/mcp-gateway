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
        warnings.to_lowercase().contains("audit") || warnings.contains(DECISION_KIND),
        "row 7: the failed decision write was not logged:\n{warnings}"
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
