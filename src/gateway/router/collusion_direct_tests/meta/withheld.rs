// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8340 row 7 over HTTP (`/mcp`, lead ruling: the owner is proven per
//! entry). A grant-withheld surfaced personal capability writes exactly one
//! decision record per call, and under `FailClosed` with that record failing
//! it answers exactly as the unsurfaced name; the failure is logged, and the
//! next record of the kind appends. RED on base (the failure answers -32005).

use super::*;
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, DECISION_KIND, PERSONAL, capability_backend, grant, grants, logger, wait_for_decisions,
};
use crate::security::audit::AuditFailurePolicy;

/// The documented warning of a withheld record that could not be written.
const WARNING: &str = "The audit record of a withheld surfaced call could not be written";

const ALICE: (&str, &str) = ("https://idp.example.invalid", "alice-sub");
const BOB: (&str, &str) = ("https://idp.example.invalid", "bob-sub");

fn verified((issuer, subject): (&str, &str)) -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity::for_test(
        subject.to_string(),
        format!("{subject}@example.invalid"),
        None,
        vec![],
        issuer.to_string(),
    )
}

/// The capability owned by alice, granted to alice only, logging under
/// `FailClosed` to `dir`; surfaced when `surface`.
async fn gateway(
    port: u16,
    dir: &Arc<tempfile::TempDir>,
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
    let (_, body) = post_with(
        fx,
        Some("a"),
        PERSONAL,
        &json!({}),
        &json!({}),
        Some(verified(who)),
    )
    .await;
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
    let control_dir = Arc::new(tempfile::tempdir().unwrap());
    let (control, _) = runtime.block_on(gateway(endpoint.port, &control_dir, true));
    let allowed = runtime.block_on(call(&control, ALICE));
    assert!(
        allowed.get("error").is_none() && endpoint.arrivals() == 1,
        "premise: the granted control did not succeed: {allowed}"
    );
    // One record per withheld call, no fault armed.
    let counted_dir = Arc::new(tempfile::tempdir().unwrap());
    let (counted, _) = runtime.block_on(gateway(endpoint.port, &counted_dir, true));
    let refused = runtime.block_on(call(&counted, BOB));
    assert_eq!(
        endpoint.arrivals(),
        1,
        "premise: the withheld call ran: {refused}"
    );
    // Written after the call settles, on the slot's own task.
    let one = runtime.block_on(wait_for_decisions(&counted_dir, 1)).len();
    // Under a failing decision record.
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let absent_dir = Arc::new(tempfile::tempdir().unwrap());
    let (withheld, log) = runtime.block_on(gateway(endpoint.port, &dir, true));
    let (absent, _) = runtime.block_on(gateway(endpoint.port, &absent_dir, false));
    log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let (answered, warnings) = crate::test_log_capture::capture_warnings(|| {
        runtime.block_on(async {
            let answer = call(&withheld, BOB).await;
            // The record is appended after the call settles: wait for the
            // attempt, then let its failure be logged.
            let attempts = crate::gateway::meta_mcp::grant_audit::seams::appends_for_test();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while crate::gateway::meta_mcp::grant_audit::seams::appends_for_test() == attempts
                && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            // The attempt has started: wait for its blocking write to finish,
            // then let the detached task log the failure.
            let drained = Arc::clone(&log);
            let _ = tokio::task::spawn_blocking(move || {
                drained.wait_write_cleared_for_test(crate::test_wait::HANG_BOUND)
            })
            .await;
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            answer
        })
    });
    let expected = runtime.block_on(call(&absent, BOB));
    runtime.block_on(call(&withheld, BOB));
    let after = runtime.block_on(wait_for_decisions(&dir, 1)).len();
    assert_eq!(
        (one, &answered, after),
        (1, &expected, 1),
        "row 7 http: records per call {one}; withheld {answered} vs absent {expected}; \
         records after the failed one {after}\n{warnings}"
    );
    assert!(
        // The text, as the upgrade note documents it for operators.
        warnings.contains(WARNING),
        "row 7 http: the failed decision write was not logged as documented:\n{warnings}"
    );
}
