// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 row 7 over HTTP (`/mcp`, lead ruling: the owner is proven per
//! entry). A grant-withheld surfaced personal capability writes exactly one
//! decision record per call, and under `FailClosed` with that record failing
//! it answers exactly as the unsurfaced name; the failure is logged, and the
//! next record of the kind appends. RED on base (the failure answers -32005).

use super::*;
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, DECISION_KIND, PERSONAL, capability_backend, decisions, grant, grants, logger,
};
use crate::security::audit::AuditFailurePolicy;

const ALICE: (&str, &str) = ("https://idp.example.invalid", "alice-sub");
const BOB: (&str, &str) = ("https://idp.example.invalid", "bob-sub");

fn verified((issuer, subject): (&str, &str)) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: vec![],
        issuer: issuer.to_string(),
    }
}

/// The capability owned by alice, granted to alice only, logging under
/// `FailClosed` to `dir`; surfaced when `surface`.
async fn gateway(
    port: u16,
    dir: &tempfile::TempDir,
    surface: bool,
) -> (Fixture, Arc<crate::security::TransparencyLogger>) {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let armed = Arc::clone(&log);
    let fx = meta_fixture_with(Setup::default(), None, move |meta| {
        let mut meta = if surface {
            meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
                server: CAPS.to_string(),
                tool: PERSONAL.to_string(),
            }])
        } else {
            meta
        };
        meta.enable_transparency_log(armed);
        meta.set_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]));
        meta.set_capabilities(capability_backend(port, ALICE));
        meta
    })
    .await;
    (fx, log)
}

async fn call(fx: &Fixture, who: (&str, &str)) -> Value {
    let (_, body) = post_with(fx, Some("a"), PERSONAL, &json!({}), &json!({}), Some(verified(who))).await;
    envelope(&body)
}

#[test]
fn row7_http_one_grant_record_and_failclosed_answers_as_absent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let endpoint =
        runtime.block_on(crate::gateway::meta_mcp::grant_audit_fixture::Endpoint::start(false));
    // Premise: the granted owner's fresh call succeeds; bob's reaches nothing.
    let control_dir = tempfile::tempdir().unwrap();
    let (control, _) = runtime.block_on(gateway(endpoint.port, &control_dir, true));
    let allowed = runtime.block_on(call(&control, ALICE));
    assert!(
        allowed.get("error").is_none() && endpoint.arrivals() == 1,
        "premise: the granted control did not succeed: {allowed}"
    );
    // One record per withheld call, no fault armed.
    let counted_dir = tempfile::tempdir().unwrap();
    let (counted, _) = runtime.block_on(gateway(endpoint.port, &counted_dir, true));
    let refused = runtime.block_on(call(&counted, BOB));
    assert_eq!(endpoint.arrivals(), 1, "premise: the withheld call ran: {refused}");
    let one = decisions(&counted_dir).len();
    // Under a failing decision record.
    let dir = tempfile::tempdir().unwrap();
    let absent_dir = tempfile::tempdir().unwrap();
    let (withheld, log) = runtime.block_on(gateway(endpoint.port, &dir, true));
    let (absent, _) = runtime.block_on(gateway(endpoint.port, &absent_dir, false));
    log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let (answered, warnings) =
        crate::test_log_capture::capture_warnings(|| runtime.block_on(call(&withheld, BOB)));
    let expected = runtime.block_on(call(&absent, BOB));
    runtime.block_on(call(&withheld, BOB));
    let after = decisions(&dir).len();
    assert_eq!(
        (one, &answered, after),
        (1, &expected, 1),
        "row 7 http: records per call {one}; withheld {answered} vs absent {expected}; \
         records after the failed one {after}\n{warnings}"
    );
    assert!(
        warnings.to_lowercase().contains("audit") || warnings.contains(DECISION_KIND),
        "row 7 http: the failed decision write was not logged:\n{warnings}"
    );
}
