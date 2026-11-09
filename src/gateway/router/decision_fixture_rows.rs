// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table, HTTP rows: one concrete call per decider site
//! on the direct route (`/mcp/{backend}`) and the meta route's HTTP gate
//! (`/mcp`), each pinning its whole decision with `assert_row`.
//!
//! What every refusal row pins, read at 01aa22f2cc:
//! - `rule_id` absent: each site below notes its kind with `None`.
//! - `grant_id` absent: the decision constructor sets `grant_id: None`
//!   (`decision_record.rs:304`); flipped when a writer of the decision's
//!   grant id lands.
//! - findings `NotRun`: no production writer of `request_findings` yet;
//!   flipped when the request-findings writer lands.
//! - no effect: an effect is noted only after admission.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, fixture_logged, post_direct, post_meta_invoke};
use crate::gateway::meta_mcp::grant_audit_fixture::{entries, logger};
use crate::security::audit::AuditFailurePolicy;
use crate::security::decision_fixture_table::{DecisionRow, Findings, RuleId, assert_row};

/// How a refused call is answered to its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// A `result` with `isError: true`.
    IsErrorResult,
    /// A JSON-RPC `error`.
    RpcError,
}

/// What a refusal row expects of the call's answer and record, each value
/// read from the source line its row cites.
#[derive(Debug, Clone, Copy)]
struct Refusal {
    status: StatusCode,
    form: Form,
    /// The record's `outcome`.
    outcome: &'static str,
    /// The record's `error_code`; `None` requires the key absent.
    code: Option<i64>,
}

/// A table gateway logging both routes to `dir`.
async fn table(dir: &Arc<tempfile::TempDir>) -> Fx {
    let log = logger(dir, AuditFailurePolicy::FailClosed);
    let meta_log = Arc::clone(&log);
    fixture_logged(Answer::Ok, log, |mut meta| {
        meta.enable_transparency_log(meta_log);
        meta
    })
    .await
}

/// The invocation records in `dir`'s log: entries naming a tool that are not
/// delivery attempts.
fn records(dir: &tempfile::TempDir) -> Vec<Value> {
    entries(dir)
        .into_iter()
        .filter(|e| e.get("tool").is_some() && e["event"] != "response_delivery_attempt")
        .collect()
}

/// Checks a refused call's `(status, body)` and its one new record against
/// `want`, and that the backend was sent nothing; returns the decision.
fn refused(
    fx: &Fx,
    dir: &tempfile::TempDir,
    (status, body): (StatusCode, Value),
    (before, sent): (usize, usize),
    want: Refusal,
) -> Value {
    assert_eq!(status, want.status, "the answer's status: {body}");
    let form = if body.get("error").is_some() {
        Form::RpcError
    } else {
        assert_eq!(body["result"]["isError"], true, "premise: refused: {body}");
        Form::IsErrorResult
    };
    assert_eq!(form, want.form, "the answer's form: {body}");
    assert_eq!(
        super::direct_continuation_tests::dispatched(fx),
        sent,
        "the backend was sent the call: {body}"
    );
    let mut all = records(dir);
    let new = all.split_off(before);
    let [record] = new.as_slice() else {
        panic!("premise: one new invocation record: {new:?}; answer {body}");
    };
    assert_eq!(record["outcome"], want.outcome, "{body}: {record}");
    assert_eq!(
        record.get("error_code").and_then(Value::as_i64),
        want.code,
        "{body}: {record}"
    );
    if want.code.is_none() {
        assert!(record.get("error_code").is_none(), "{body}: {record}");
    }
    record["decision"].clone()
}

/// A refusal row: `kind` at a kind-only site, nothing else recorded.
const fn refusal(name: &'static str, kind: &'static str, absent: &'static str) -> DecisionRow {
    DecisionRow {
        name,
        kind,
        rule_id: RuleId::Absent(absent),
        grant_id: None,
        findings: Findings::NotRun,
        effect: None,
        decided: "fresh",
    }
}

/// `backend_not_found` answers HTTP 404 with -32001 (`direct_caller.rs:419-425`);
/// a non-200 answer is classified by its status (`direct_audit.rs:92-93`), and
/// 404 reads as `invalid` with the body's code (`audit.rs:130`).
const NOT_FOUND: Refusal = Refusal {
    status: StatusCode::NOT_FOUND,
    form: Form::RpcError,
    outcome: "invalid",
    code: Some(-32001),
};

/// N4: a scoped key names a backend in its grant that is not registered; the
/// scoped view's absence notes `not_found` (`direct_caller.rs:345`, via
/// `note_absent`, `:257`).
#[tokio::test]
async fn n4_direct_not_found_in_a_scoped_view() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer = post_direct(&fx, "ghost", "k-alpha-ghost", "read", json!({}), None, None).await;
    let decision = refused(&fx, &dir, answer, before, NOT_FOUND);
    assert_row(
        &decision,
        &refusal(
            "n4_direct_not_found_in_a_scoped_view",
            "not_found",
            "the target matches nothing",
        ),
    );
}

/// N5: an unscoped key names a backend that matches nothing; `backend_for`
/// finds none (`direct_caller.rs:487`).
#[tokio::test]
async fn n5_direct_not_found_by_lookup() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer = post_direct(&fx, "nowhere", "k-std", "read", json!({}), None, None).await;
    let decision = refused(&fx, &dir, answer, before, NOT_FOUND);
    assert_row(
        &decision,
        &refusal(
            "n5_direct_not_found_by_lookup",
            "not_found",
            "the target matches nothing",
        ),
    );
}

/// N1: on the meta route's HTTP gate, a scoped key names a server in its
/// grant that is not registered: the gate answers the absent step
/// (`gate.rs:544` in `absent_answer`, from `gate_answer`, `gate.rs:584`). The
/// in-process `invoke_tool` skips this gate (it reaches N2's site instead).
#[tokio::test]
async fn n1_meta_not_found_at_the_gate() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer =
        post_meta_invoke(&fx, "k-alpha-ghost", "ghost", "read", json!({}), None, None).await;
    // The gate's absent answer is an `isError` result naming the tool as
    // unlisted, on a 200; the gate marks the miss not-found (`gate.rs:545`),
    // so the record is `denied` with the miss's -32001 (`denial.rs:44-47`).
    let absent = Refusal {
        status: StatusCode::OK,
        form: Form::IsErrorResult,
        outcome: "denied",
        code: Some(-32001),
    };
    let decision = refused(&fx, &dir, answer, before, absent);
    assert_row(
        &decision,
        &refusal(
            "n1_meta_not_found_at_the_gate",
            "not_found",
            "the target matches nothing",
        ),
    );
}

/// T2: the backend's `allowed_tools` leaves `read` out; the direct preflight
/// withholds it (`direct_preflight.rs:60`, via `blocked_tool_kind`).
#[tokio::test]
async fn t2_direct_allowed_tools() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let config = crate::config::BackendConfig {
        allowed_tools: Some(vec!["write".to_string()]),
        ..crate::config::BackendConfig::default()
    };
    let calls = super::direct_guards_fixture::replace_backend_configured(&fx, "alpha", config);
    let before = records(&dir).len();
    let answer = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    // On a shared backend a withheld name takes the catalogue's absent answer
    // (`key_check.rs:147-170`, text from `input_keys.rs:101`): an `isError`
    // result on a 200. No denial code is noted for it, so the record reads the
    // answer: `tool_error`, with no code (`direct_audit.rs:97-99`).
    let withheld = Refusal {
        status: StatusCode::OK,
        form: Form::IsErrorResult,
        outcome: "tool_error",
        code: None,
    };
    let decision = refused(&fx, &dir, answer, (before, 0), withheld);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "alpha was sent the call"
    );
    assert_row(
        &decision,
        &refusal(
            "t2_direct_allowed_tools",
            "allowed_tools",
            "kind-only site: noted with no rule id",
        ),
    );
}

/// C2: a disabled capability, met at the direct admission
/// (`dispatch_guards.rs:319` in `admit_target`, via `direct_guards.rs:36`).
#[tokio::test]
async fn c2_direct_capability_disabled() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let budget = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    let kill = fx.state.meta_mcp.kill_switch();
    for _ in 0..20 {
        kill.record_capability_failure("alpha", "read", &budget);
    }
    assert!(
        kill.is_capability_disabled("alpha", "read"),
        "premise: the capability is disabled"
    );
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    // The refusal is answered with its own code, -32000 (`dispatch_guards.rs:308`),
    // as a JSON-RPC error on a 200 (`direct_dispatch.rs:265-270`), read as
    // `error` with that code (`direct_audit.rs:94-96`).
    let disabled = Refusal {
        status: StatusCode::OK,
        form: Form::RpcError,
        outcome: "error",
        code: Some(-32000),
    };
    let decision = refused(&fx, &dir, answer, before, disabled);
    assert_row(
        &decision,
        &refusal(
            "c2_direct_capability_disabled",
            "capability_disabled",
            "kind-only site: noted with no rule id",
        ),
    );
}

/// P3: the session's routing profile leaves `read` out, met in the direct
/// preflight before any credential (`direct_preflight.rs:51`). P4, the same
/// check at the direct admission (`dispatch_guards.rs:204` via
/// `direct_guards.rs:36`), runs after it on the same profile, so it refuses
/// only when the profile changes between the two (a reload guard); that site
/// is pinned by the unit row `p4_admission_routing_profile`.
#[tokio::test]
async fn p3_direct_routing_profile_preflight() {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let meta_log = Arc::clone(&log);
    let profiles = std::collections::HashMap::from([(
        "restricted".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["read".to_string()]),
            ..RoutingProfileConfig::default()
        },
    )]);
    let fx = fixture_logged(Answer::Ok, log, |mut meta| {
        meta.enable_transparency_log(meta_log);
        meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "restricted"))
    })
    .await;
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let answer = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    // Answered with the shared catalogue's absent answer, an `isError` result
    // on a 200 (`key_check.rs:147-170`); the preflight notes the profile
    // refusal's own code, `Error::Protocol`'s -32600
    // (`backend_handlers.rs:162-167`), so the record is `denied` with it
    // (`direct_audit.rs:353-358`).
    let withheld_by_profile = Refusal {
        status: StatusCode::OK,
        form: Form::IsErrorResult,
        outcome: "denied",
        code: Some(-32600),
    };
    let decision = refused(&fx, &dir, answer, before, withheld_by_profile);
    assert_row(
        &decision,
        &refusal(
            "p3_direct_routing_profile_preflight",
            "routing_profile",
            "kind-only site: noted with no rule id",
        ),
    );
}

/// Whether `alpha`'s identity propagation is required. Both keep per-user
/// catalogues (a session mode is set, `pool.rs:375-377`); they differ for
/// `k-std`, whose API key carries no verified identity and so no principal
/// (`propagation.rs:276-285`).
#[derive(Clone, Copy)]
enum Propagation {
    /// `k-std` lacks a principal on a backend that requires one
    /// (`listing_view.rs:112-120`), so the gate answers its withheld name
    /// with its own absent answer (`direct_gate.rs:95-109`), not the one
    /// `key_check` built.
    Required,
    /// Nothing is lacked, so the gate returns the answer `key_check` built
    /// for the withheld name (`direct_gate.rs:71-84`, `key_check.rs:84-86`,
    /// built at `key_check.rs:24-27`), and the route sends it
    /// (`backend_handlers.rs:576`).
    Optional,
}

/// `alpha` as a per-user backend: the propagating fixture's config
/// (propagation to `aud-alpha`, stateless sessions, over HTTP), so it keeps
/// per-user catalogues (`pool.rs:375-377`), with `allowed`.
fn per_user_alpha(
    allowed: Option<Vec<String>>,
    propagation: Propagation,
) -> crate::config::BackendConfig {
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "https://alpha.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "aud-alpha".to_string(),
            required: matches!(propagation, Propagation::Required),
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        allowed_tools: allowed,
        ..crate::config::BackendConfig::default()
    }
}

/// On a per-user backend, a withheld name is answered as an absent one:
/// `absent_name`'s `METHOD_NOT_FOUND` (-32601, `absent.rs:9-11`) as a
/// JSON-RPC error on a 200, from either site [`Propagation`] names
/// (`direct_gate.rs:100-108`, `key_check.rs:24-27`).
const PER_USER_ABSENT: (StatusCode, Form, i64) = (StatusCode::OK, Form::RpcError, -32601);

/// T2b: T2 on a per-user backend (found while coding: the per-user and the
/// shared catalogue answer a withheld name at different sites), with
/// propagation required: answered at `direct_gate.rs:95-109`.
#[tokio::test]
async fn t2b_direct_allowed_tools_per_user() {
    allowed_tools_per_user("t2b_direct_allowed_tools_per_user", Propagation::Required).await;
}

/// T2c: T2b with propagation optional: answered from `key_check.rs:84-86`.
#[tokio::test]
async fn t2c_direct_allowed_tools_per_user_optional() {
    allowed_tools_per_user(
        "t2c_direct_allowed_tools_per_user_optional",
        Propagation::Optional,
    )
    .await;
}

/// T2b and T2c. No denial code is noted, so the record reads the answer:
/// `error` with its code (`direct_audit.rs:94-96`), whichever site built it.
async fn allowed_tools_per_user(row: &'static str, propagation: Propagation) {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let calls = super::direct_guards_fixture::replace_backend_configured(
        &fx,
        "alpha",
        per_user_alpha(Some(vec!["write".to_string()]), propagation),
    );
    assert!(
        fx.state
            .backends
            .get("alpha")
            .expect("alpha")
            .keeps_per_user_catalogues(),
        "premise: alpha keeps per-user catalogues"
    );
    let before = records(&dir).len();
    let answer = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    let (status, form, code) = PER_USER_ABSENT;
    let withheld = Refusal {
        status,
        form,
        outcome: "error",
        code: Some(code),
    };
    // The code the caller is answered with, checked on its own: `absent_name`'s
    // METHOD_NOT_FOUND (`absent.rs:9-11`), whatever the record keeps.
    assert_eq!(
        answer.1.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "the answer's code: {}",
        answer.1
    );
    let decision = refused(&fx, &dir, answer, (before, 0), withheld);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "alpha was sent the call"
    );
    assert_row(
        &decision,
        &refusal(
            row,
            "allowed_tools",
            "kind-only site: noted with no rule id",
        ),
    );
}

/// P3b: P3 on a per-user backend (found while coding, with T2b), with
/// propagation required: answered at `direct_gate.rs:95-109`.
#[tokio::test]
async fn p3b_direct_routing_profile_preflight_per_user() {
    routing_profile_per_user(
        "p3b_direct_routing_profile_preflight_per_user",
        Propagation::Required,
    )
    .await;
}

/// P3c: P3b with propagation optional: answered from `key_check.rs:84-86`.
#[tokio::test]
async fn p3c_direct_routing_profile_preflight_per_user_optional() {
    routing_profile_per_user(
        "p3c_direct_routing_profile_preflight_per_user_optional",
        Propagation::Optional,
    )
    .await;
}

/// P3b and P3c. The preflight notes the profile refusal's -32600
/// (`backend_handlers.rs:162-167`), so the record is `denied` with it
/// (`direct_audit.rs:353-358`), whichever site built the answer.
async fn routing_profile_per_user(row: &'static str, propagation: Propagation) {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let meta_log = Arc::clone(&log);
    let profiles = std::collections::HashMap::from([(
        "restricted".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["read".to_string()]),
            ..RoutingProfileConfig::default()
        },
    )]);
    let fx = fixture_logged(Answer::Ok, log, |mut meta| {
        meta.enable_transparency_log(meta_log);
        meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "restricted"))
    })
    .await;
    let calls = super::direct_guards_fixture::replace_backend_configured(
        &fx,
        "alpha",
        per_user_alpha(None, propagation),
    );
    let before = records(&dir).len();
    let answer = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    let (status, form, _) = PER_USER_ABSENT;
    let withheld = Refusal {
        status,
        form,
        outcome: "denied",
        code: Some(-32600),
    };
    // The code the caller is answered with, checked on its own: `absent_name`'s
    // METHOD_NOT_FOUND (`absent.rs:9-11`), whatever the record keeps.
    assert_eq!(
        answer.1.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "the answer's code: {}",
        answer.1
    );
    let decision = refused(&fx, &dir, answer, (before, 0), withheld);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "alpha was sent the call"
    );
    assert_row(
        &decision,
        &refusal(
            row,
            "routing_profile",
            "kind-only site: noted with no rule id",
        ),
    );
}

/// A6b: nothing restricts a direct call (`k-std`, no tool policy). Allow
/// attribution does not flip this row. The record is `default_allow` with no rule id:
/// `Checks::allowed` has no fresh-call caller (`decision_record.rs:193, 231`),
/// so a fresh allowed call records it (`:268-272`). The effect is `alpha`'s
/// shared slot's declaration, as the live call notes it for an unpropagated
/// caller (`direct_idempotency.rs:315-325`). Control: `k-deny`, whose own
/// tool list denies `read`, is refused. Coupling: that refusal is answered
/// through the shared catalogue's absent answer (`key_check.rs:147-170`), so a
/// mutant there fails this row's control as well as T2 and P3.
#[tokio::test]
async fn a6b_direct_no_rule() {
    let dir = Arc::new(tempfile::tempdir().expect("a log directory"));
    let fx = table(&dir).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    let read: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read",
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true},
    }))
    .expect("a tool");
    alpha.declare_slot_effects_for_test(None, vec![read]);
    let before = (
        records(&dir).len(),
        super::direct_continuation_tests::dispatched(&fx),
    );
    let (status, body) = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("result").is_some() && body["result"]["isError"] != true,
        "premise: delivered: {body}"
    );
    assert_eq!(
        super::direct_continuation_tests::dispatched(&fx),
        before.1 + 1,
        "premise: the backend was sent the call once"
    );
    let mut all = records(&dir);
    let new = all.split_off(before.0);
    let [record] = new.as_slice() else {
        panic!("premise: one new invocation record: {new:?}");
    };
    assert_eq!(record["outcome"], "ok", "{record}");
    let row = DecisionRow {
        name: "a6b_direct_no_rule",
        kind: "default_allow",
        rule_id: RuleId::Absent("no rule restricted this call"),
        grant_id: None,
        findings: Findings::NotRun,
        effect: Some(("read_only", "tool_annotation")),
        decided: "fresh",
    };
    assert_row(&record["decision"], &row);
    let sent = super::direct_continuation_tests::dispatched(&fx);
    let (status, body) = post_direct(&fx, "alpha", "k-deny", "read", json!({}), None, None).await;
    assert!(
        body.get("error").is_some() || body["result"]["isError"] == true,
        "control: k-deny was not refused: {status} {body}"
    );
    assert_eq!(
        super::direct_continuation_tests::dispatched(&fx),
        sent,
        "control: the backend was sent k-deny's call"
    );
}

/// A3: an execute grant admits the owner's call to its personal capability
/// on the meta route. Records the grant as the allowing check, its keyed id
/// and the operator's `grant_id` (flipped by allow attribution). The effect is the capability's own definition,
/// `read_only: true` (`pre_dispatch.rs:77-86`). Control: without the grant,
/// the same call is refused and the upstream is not hit.
#[tokio::test]
async fn a3_grant_match() {
    use super::direct_effect_tests::{CAPS, PROBE, call, owned_capability};
    let (fx, hits, dir) = owned_capability(true).await;
    // The keyed id the published grant store holds for the matched grant.
    let held = {
        let (live, _) = fx.state.meta_mcp.identity_grant_sink();
        let id = live.read().rule_id("g-direct-probe").cloned();
        id.expect("premise: the store holds an id for g-direct-probe")
    };
    let before = records(&dir).len();
    let answer = call(
        &fx,
        "/mcp",
        "gateway_invoke",
        json!({"server": CAPS, "tool": PROBE, "arguments": {}}),
    )
    .await;
    assert!(
        answer.to_string().contains("served-1"),
        "premise: delivered: {answer}"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: one upstream hit"
    );
    let mut all = records(&dir);
    let new = all.split_off(before);
    // The grant check writes its own record beside the invocation's
    // (`GrantNote::project`, `grant_audit.rs:127-163`): kind
    // `identity_grant_decision` (`:45`, `:129`), the matched `grant_id` (`:143-145`),
    // and no decision object among its fields.
    let granted: Vec<&Value> = new.iter().filter(|r| r.get("decision").is_none()).collect();
    assert!(
        matches!(granted.as_slice(), [grant]
            if grant["grant_id"] == "g-direct-probe"
                && grant["kind"] == "identity_grant_decision"
                // An allowed grant's record is `ok` (`grant_audit.rs:185-186`).
                && grant["outcome"] == "ok"),
        "premise: one grant record naming the matched grant: {new:?}"
    );
    let invoked: Vec<&Value> = new.iter().filter(|r| r.get("decision").is_some()).collect();
    let [record] = invoked.as_slice() else {
        panic!("premise: one invocation record: {new:?}");
    };
    assert_eq!(record["outcome"], "ok", "{record}");
    // flipped by allow attribution
    let row = DecisionRow {
        name: "a3_grant_match",
        kind: "grant",
        rule_id: RuleId::named(held.as_str()),
        grant_id: Some("g-direct-probe"),
        findings: Findings::NotRun,
        effect: Some(("read_only", "capability_definition")),
        decided: "fresh",
    };
    assert_row(&record["decision"], &row);

    let (fx, hits, _dir) = owned_capability(false).await;
    let answer = call(
        &fx,
        "/mcp",
        "gateway_invoke",
        json!({"server": CAPS, "tool": PROBE, "arguments": {}}),
    )
    .await;
    assert!(
        !answer.to_string().contains("served-"),
        "control: served without the grant: {answer}"
    );
    // Refused as the grant check refuses it: an unreachable capability answers
    // as an undefined one, `Error::ToolNotFound` (`gate.rs:678-690`), whose
    // text is "Tool not found: '<tool>'" (`error.rs:284`); a non-null error or a
    // result marked `isError`.
    assert!(
        answer
            .to_string()
            .contains(&format!("Tool not found: '{PROBE}'")),
        "control: not the grant check's refusal: {answer}"
    );
    assert!(
        answer.get("error").is_some_and(|e| !e.is_null()) || answer["result"]["isError"] == true,
        "control: no refusal without the grant: {answer}"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "control: the upstream was hit without the grant"
    );
}

#[path = "decision_fixture_mtls_rows.rs"]
mod mtls;
