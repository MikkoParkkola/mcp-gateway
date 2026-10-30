// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 audit rows (test plan v3, A1-A3) on `gateway_invoke`: a call
//! withheld from its caller by an identity grant answers as the name the
//! capability backend does not define, writes its decision record, and keeps
//! that answer when the record cannot be written (D3-a narrowed, lead ruling
//! 2026-10-11: counted, never answered). A dispatching call still fails
//! closed.

use std::sync::Arc;

use serde_json::{Value, json};

use super::MetaMcp;
use super::grant_audit_fixture::{
    CAPS, DECISION_KIND, Endpoint, PERSONAL, capability_backend, decisions, grant, grants, logger,
};
use super::grant_decision_audit_tests::{api_key, context, gateway};
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::protocol::RequestId;
use crate::security::audit::AuditFailurePolicy;

/// The capability's owner; the caller is `alice`, ungranted unless a row
/// grants her.
const ALICE: (&str, &str) = ("api_key", "alice");

/// A gateway logging to `dir` under `FailClosed` with no grants, whose
/// capability backend defines [`PERSONAL`] (`defines`) or nothing.
fn ungranted(
    endpoint: &Endpoint,
    dir: &tempfile::TempDir,
    defines: bool,
) -> (MetaMcp, Arc<crate::security::TransparencyLogger>) {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()))
        .with_identity_grants(grants(vec![]));
    meta.enable_transparency_log(Arc::clone(&log));
    let caps = if defines {
        capability_backend(endpoint.port, ALICE)
    } else {
        Arc::new(CapabilityBackend::new(
            CAPS,
            Arc::new(CapabilityExecutor::new()),
        ))
    };
    meta.set_capabilities(caps);
    (meta, log)
}

/// alice's `gateway_invoke` of [`PERSONAL`], as the client receives it.
async fn invoke(meta: &MetaMcp) -> Value {
    let who = api_key("alice");
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_invoke",
        json!({"server": CAPS, "tool": PERSONAL, "arguments": {}}),
        Some("o-audit"),
        context(&who),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serialises")
}

/// A1 + A2: the withheld call answers as the undefined name, writes its
/// decision record, and during an audit outage still answers so, with the
/// failed append counted exactly once. RED on base: the grant refusal
/// (-32004), and -32005 during the outage.
#[tokio::test]
async fn a1_a2_a_withheld_call_is_recorded_and_an_outage_is_counted_not_answered() {
    let endpoint = Endpoint::start(false).await;
    let (absent_dir, dir, outage_dir) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    let absent = invoke(&ungranted(&endpoint, &absent_dir, false).0).await;
    let mut cells = Vec::new();
    // A1: no outage.
    let (withheld, _) = ungranted(&endpoint, &dir, true);
    let answered = invoke(&withheld).await;
    if answered != absent {
        cells.push(format!("A1: withheld {answered} vs undefined {absent}"));
    }
    if decisions(&dir).is_empty() {
        cells.push("A1: no decision record was written".to_string());
    }
    // A2: the decision append fails.
    let (withheld, log) = ungranted(&endpoint, &outage_dir, true);
    let before = log.append_failures();
    log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let answered = invoke(&withheld).await;
    if answered != absent {
        cells.push(format!(
            "A2: withheld during the outage {answered} vs undefined {absent}"
        ));
    }
    let counted = log.append_failures() - before;
    if counted != 1 {
        cells.push(format!("A2: {counted} append failures counted, expected 1"));
    }
    assert_eq!(
        endpoint.arrivals(),
        0,
        "a withheld call reached the endpoint"
    );
    assert!(cells.is_empty(), "A1/A2:\n{}", cells.join("\n"));
}

/// A3: a granted, dispatching call whose decision append fails still answers
/// -32005 (D3-a kept for every path that can dispatch). GREEN on base; the
/// mutant applying the narrowing to dispatching calls must fail it.
#[tokio::test]
async fn a3_a_dispatching_call_during_an_outage_still_fails_closed() {
    let endpoint = Endpoint::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let meta = gateway(
        &endpoint,
        vec![grant("g1", ALICE, ALICE)],
        Some(&dir),
        AuditFailurePolicy::FailClosed,
    );
    let log = meta.transparency_logger.clone().expect("the fixture logs");
    log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let answered = invoke(&meta).await;
    assert_eq!(
        answered.pointer("/error/code"),
        Some(&json!(-32005)),
        "A3: a dispatching call's failed decision write did not fail closed: {answered}"
    );
}

/// A second personal capability, owned by bob: alice holds no grant for it.
const OTHER: &str = "calendar_peek_day";

/// A gateway logging to `dir` under `FailClosed` where alice is granted
/// [`PERSONAL`]; [`OTHER`] is defined (withheld from alice, `defines`) or not.
fn mixed(
    endpoint: &Endpoint,
    dir: &tempfile::TempDir,
    defines: bool,
) -> (MetaMcp, Arc<crate::security::TransparencyLogger>) {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let mut meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()))
        .with_identity_grants(grants(vec![grant("g1", ALICE, ALICE)]));
    meta.enable_transparency_log(Arc::clone(&log));
    let caps = capability_backend(endpoint.port, ALICE);
    if defines {
        let other = crate::capability::parse_capability(&format!(
            "name: {OTHER}\n\
             description: Peek one calendar day\n\
             metadata:\n\
             \x20 exposure: personal\n\
             \x20 read_only: true\n\
             \x20 identity_owner:\n\
             \x20   authority: api_key\n\
             \x20   subject: bob\n\
             providers:\n\
             \x20 primary:\n\
             \x20   service: rest\n\
             \x20   config:\n\
             \x20     base_url: {}\n\
             \x20     path: /read\n\
             \x20     method: GET\n",
            crate::test_fixture_host::fixture_url(endpoint.port)
        ))
        .expect("the second capability parses");
        caps.register_capability(other)
            .expect("the second capability registers");
    }
    meta.set_capabilities(caps);
    (meta, log)
}

/// alice's chain: the granted [`PERSONAL`], then [`OTHER`].
async fn chain(meta: &MetaMcp) -> Value {
    let who = api_key("alice");
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_execute",
        json!({"chain": [
            {"tool": format!("{CAPS}:{PERSONAL}"), "arguments": {}},
            {"tool": format!("{CAPS}:{OTHER}"), "arguments": {}}
        ]}),
        Some("o-audit-chain"),
        context(&who),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serialises")
}

/// A3a (v3 item 1): in one request, the withheld step's own decision append
/// fails and nothing else does. The chain answers as the chain whose second
/// step is undefined, and the granted step's record is still written. RED on
/// base: the failed append answers -32005.
#[tokio::test]
async fn a3a_a_withheld_steps_failed_record_is_isolated() {
    use super::grant_audit::seams;
    let endpoint = Endpoint::start(false).await;
    let (absent_dir, dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let absent = chain(&mixed(&endpoint, &absent_dir, false).0).await;
    let (withheld, _log) = mixed(&endpoint, &dir, true);
    // The withheld step's note is written at once, before the request-end
    // flush of the granted step's: the first grant-record append from now.
    seams::fail_append_at_for_test(1);
    let answered = chain(&withheld).await;
    assert_eq!(
        answered, absent,
        "A3a: withheld {answered} vs undefined {absent}"
    );
    assert!(
        decisions(&dir)
            .iter()
            .any(|d| d.to_string().contains(PERSONAL)),
        "A3a: the granted step's record was not written: {:?}",
        decisions(&dir)
    );
}

/// A3b (v3 item 1): in the same request, the granted step's request-end
/// append fails: that call answers -32005, as MIK-8340 row 7b pins (D3-a kept
/// for what dispatched). GREEN on base; mutant MA2 (unrelated notes made
/// best-effort) must fail it.
#[tokio::test]
async fn a3b_another_steps_failed_record_still_fails_closed() {
    use super::grant_audit::seams;
    let endpoint = Endpoint::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (withheld, _log) = mixed(&endpoint, &dir, true);
    seams::fail_append_at_for_test(2);
    let answered = chain(&withheld).await;
    assert_eq!(
        answered.pointer("/error/code"),
        Some(&json!(-32005)),
        "A3b: the granted step's failed record did not fail closed: {answered}"
    );
}
