// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Calls refused by an identity grant, through `/mcp`, read back through the
//! Activity route: a refusal with no invocation record of its own is one
//! blocked row, and a call with an invocation record is one row. Every row
//! asserts the raw record counts first.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::meta_fixture::test_router_app_state_with_logs;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, grant, grants, invocations, logger,
    wait_for_decisions,
};
use crate::security::audit::AuditFailurePolicy;

const ISSUER: &str = "https://idp.example.invalid";
const SUBJECT: &str = "alice-sub";
const ADMIN_KEY: &str = "refusal-admin-key";
const CALLER_KEY: &str = "refusal-caller-key";

fn key(secret: &str, admin: bool, denied: Option<&str>) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: secret.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: denied.map(|tool| vec![tool.to_string()]),
        admin,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// A gateway whose Meta-MCP and Activity route share one log in `dir`.
struct Rig {
    state: Arc<AppState>,
    dir: Arc<tempfile::TempDir>,
    _store: super::tests::FixtureDir,
}

/// The personal capability is owned by the caller, who holds no grant. It is
/// surfaced when `surface`, and the caller's key denies it when `denied`.
async fn rig(endpoint: &Endpoint, policy: AuditFailurePolicy, surface: bool, denied: bool) -> Rig {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = logger(&dir, policy);
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![
            key(ADMIN_KEY, true, None),
            key(CALLER_KEY, false, denied.then_some(PERSONAL)),
        ],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (mut state, store) =
        test_router_app_state_with_logs(&auth, Some(Arc::clone(&log)), None).await;
    let st = Arc::get_mut(&mut state).expect("state is unique");
    let mut meta = MetaMcp::with_features(
        Arc::clone(&st.backends),
        None,
        None,
        None,
        Duration::from_secs(600),
    )
    .with_code_mode(true);
    meta.set_live_config(Arc::clone(&st.live_config));
    meta.enable_transparency_log(log);
    if surface {
        meta = meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: CAPS.to_string(),
            tool: PERSONAL.to_string(),
        }]);
    }
    meta.set_identity_grants(grants(vec![]));
    meta.set_capabilities(capability_backend(endpoint.port, (ISSUER, SUBJECT)));
    st.meta_mcp = Arc::new(meta);
    Rig {
        state,
        dir,
        _store: store,
    }
}

fn identity() -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity::for_test(
        SUBJECT.to_string(),
        format!("{SUBJECT}@example.invalid"),
        None,
        vec![],
        ISSUER.to_string(),
    )
}

/// This rig with message signing switched on (a nonce optional), so a
/// `gateway_invoke` carrying a nonce argument is judged while signing is
/// prepared.
async fn signed_rig(endpoint: &Endpoint) -> Rig {
    let mut rig = rig(endpoint, AuditFailurePolicy::BestEffort, false, false).await;
    let signer = crate::security::message_signing::MessageSigner::new(
        b"grant-refusal-rows-signing-secret".to_vec(),
        None,
        "grant-rows".to_owned(),
    );
    let state = Arc::get_mut(&mut rig.state).expect("state is unique");
    let meta = Arc::get_mut(&mut state.meta_mcp).expect("meta is unique");
    meta.enable_message_signing(signer, Duration::from_secs(300), false);
    rig
}

/// One `tools/call` of `name` by the caller, over `/mcp`.
async fn mcp_call(rig: &Rig, name: &str, arguments: &Value) -> Value {
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                      "io.modelcontextprotocol/clientCapabilities": {}});
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments, "_meta": meta}});
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .header(header::AUTHORIZATION, format!("Bearer {CALLER_KEY}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(identity());
    let router = create_router(Arc::clone(&rig.state));
    let response = router.oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    // JSON, or one SSE `data:` frame.
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (start, end) = (text.find('{'), text.rfind('}'));
    match start.zip(end) {
        Some((start, end)) => {
            serde_json::from_str(&text[start..=end]).unwrap_or(Value::String(text))
        }
        None => Value::String(text),
    }
}

/// The Activity rows an admin reads from the list route, under `query`.
async fn activity(rig: &Rig, query: &str) -> Vec<Value> {
    let router = create_router(Arc::clone(&rig.state));
    super::direct_audit_tests::activity_rows(router, ADMIN_KEY, query).await
}

/// A `gateway_invoke` whose capability target the grant denies is refused at
/// the route stage (answered as an absent tool), before any invocation record
/// exists: its decision says so, and Activity lists it once, as blocked.
#[tokio::test]
async fn a_route_refused_gateway_invoke_is_one_blocked_row() {
    let endpoint = Endpoint::start(false).await;
    let rig = rig(&endpoint, AuditFailurePolicy::BestEffort, false, false).await;

    let invoke = json!({"server": CAPS, "tool": PERSONAL, "arguments": {}});
    let answer = mcp_call(&rig, "gateway_invoke", &invoke).await;

    let held = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}: {answer}");
    assert_eq!(held[0]["outcome"], json!("denied"), "{held:#?}");
    assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
    assert!(
        invocations(&rig.dir).is_empty(),
        "no record of the call's own: {answer}"
    );
    let rows = activity(&rig, "").await;
    assert_eq!(rows.len(), 1, "{rows:#?}");
    assert_eq!(rows[0]["outcome"], json!("blocked"), "{rows:#?}");
    assert_eq!(rows[0]["server"], json!(CAPS), "{rows:#?}");
    assert_eq!(rows[0]["tool"], json!(PERSONAL), "{rows:#?}");
}

/// On `/mcp` the route stage judges the grant before signing runs, so a
/// signing refusal meets a grant note only after the grant allowed the call:
/// here a granted, signed `gateway_invoke` is sent twice with one nonce. The
/// replay's grant note was taken before any trace existed; the refusal's
/// record and that decision must still name one trace, and the decision must
/// read recorded, so Activity lists two calls as two rows (the stdio twin is
/// `grant_decision_stdio.rs`).
#[tokio::test]
async fn a_replay_refused_after_a_granted_route_shares_its_decisions_trace() {
    let endpoint = Endpoint::start(false).await;
    let rig = signed_rig(&endpoint).await;
    let owner = (ISSUER, SUBJECT);
    rig.state
        .meta_mcp
        .set_identity_grants(grants(vec![grant("g-replay", owner, owner)]));
    // Outside hardened, a `gateway_invoke` carries its nonce as an argument.
    let invoke =
        json!({"server": CAPS, "tool": PERSONAL, "arguments": {}, "nonce": "grant-rows-0001"});

    let served = mcp_call(&rig, "gateway_invoke", &invoke).await;
    assert!(
        served.get("error").is_none(),
        "premise: granted and served: {served}"
    );
    let replay = mcp_call(&rig, "gateway_invoke", &invoke).await;
    assert_eq!(
        replay["error"]["code"],
        json!(-32001),
        "premise: a replay: {replay}"
    );

    let held = wait_for_decisions(&rig.dir, 2).await;
    let calls = invocations(&rig.dir);
    assert_eq!((held.len(), calls.len()), (2, 2), "{held:#?} {calls:#?}");
    let refused = calls
        .iter()
        .find(|call| call["outcome"] != json!("ok"))
        .expect("the replay's own record");
    let decision = held
        .iter()
        .find(|decision| decision["trace_id"] == refused["trace_id"])
        .unwrap_or_else(|| panic!("no decision names the refusal's trace: {held:#?} {calls:#?}"));
    assert_eq!(decision["invocation_recorded"], json!(true), "{held:#?}");
    let rows = activity(&rig, "").await;
    assert_eq!(rows.len(), 2, "two calls, two rows: {rows:#?}");
}

/// That replay with its record's append failing, under a best-effort log:
/// answered as decided, and the replay's decision reads unrecorded, since
/// nothing landed: the refusal's trace on a note never marks it recorded.
#[tokio::test]
async fn a_replay_whose_record_fails_leaves_its_decision_unrecorded() {
    let endpoint = Endpoint::start(false).await;
    let rig = signed_rig(&endpoint).await;
    let owner = (ISSUER, SUBJECT);
    rig.state
        .meta_mcp
        .set_identity_grants(grants(vec![grant("g-replay", owner, owner)]));
    let invoke =
        json!({"server": CAPS, "tool": PERSONAL, "arguments": {}, "nonce": "grant-rows-0002"});
    let served = mcp_call(&rig, "gateway_invoke", &invoke).await;
    assert!(served.get("error").is_none(), "premise: served: {served}");
    let _ = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(
        invocations(&rig.dir).len(),
        1,
        "premise: the served call's record"
    );
    let log = rig.state.transparency_log.as_ref().expect("the rig logs");
    // The next append of route `meta` is the replay's invocation record.
    log.fail_next_append_of_kind_for_test("meta");

    let replay = mcp_call(&rig, "gateway_invoke", &invoke).await;
    assert_eq!(
        replay["error"]["code"],
        json!(-32001),
        "answered as decided: {replay}"
    );
    let held = wait_for_decisions(&rig.dir, 2).await;
    assert_eq!(invocations(&rig.dir).len(), 1, "the replay's append failed");
    let marks: Vec<&Value> = held.iter().map(|d| &d["invocation_recorded"]).collect();
    assert_eq!(marks, [&json!(true), &json!(false)], "{held:#?}");
}

/// A surfaced tool the caller's key withholds (`denied_tools`), where the
/// grant also denies, called by its own name: no invocation record, one
/// blocked row naming the server and tool, matched by its filters.
#[tokio::test]
async fn a_denied_tools_surfaced_call_is_one_blocked_row() {
    let endpoint = Endpoint::start(false).await;
    let rig = rig(&endpoint, AuditFailurePolicy::BestEffort, true, true).await;

    let answer = mcp_call(&rig, PERSONAL, &json!({})).await;

    let held = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(held.len(), 1, "{held:#?}: {answer}");
    assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
    assert!(
        invocations(&rig.dir).is_empty(),
        "no record of the call's own"
    );
    for query in [
        "",
        "&outcome=blocked",
        "&server=personal_caps",
        "&q=calendar_read_day",
    ] {
        let rows = activity(&rig, query).await;
        assert_eq!(rows.len(), 1, "{query}: {rows:#?}");
        assert_eq!(rows[0]["outcome"], json!("blocked"), "{query}: {rows:#?}");
        assert_eq!(rows[0]["tool"], json!(PERSONAL), "{query}: {rows:#?}");
    }
}

/// A playbook step the grant denies is refused at route-stage authorization:
/// the router writes the refusal's invocation record, and the step's decision
/// note is the same refusal's, so the call is one Activity row, not an
/// invocation row plus a blocked refusal row.
#[tokio::test]
async fn a_playbook_step_refused_by_a_grant_is_one_activity_row() {
    let endpoint = Endpoint::start(false).await;
    let rig = rig(&endpoint, AuditFailurePolicy::BestEffort, false, false).await;
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(
        crate::yaml::from_str(&format!(
            "name: stepped\ndescription: one personal step\non_error: abort\n\
             steps:\n  - name: read\n    server: {CAPS}\n    tool: {PERSONAL}\n"
        ))
        .expect("the playbook parses"),
    );
    rig.state.meta_mcp.set_playbook_engine(engine);

    let answer = mcp_call(&rig, "gateway_run_playbook", &json!({ "name": "stepped" })).await;

    assert!(
        answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true)),
        "premise: the step is refused: {answer}"
    );
    let _ = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(
        invocations(&rig.dir).len(),
        1,
        "the refusal's own record: {answer}"
    );
    let rows = activity(&rig, "").await;
    assert_eq!(rows.len(), 1, "one call, one row: {rows:#?}");
}

/// The same playbook as the step row above, built once.
/// Leg (e) of the one-meaning rows: a grant refusal with no invocation record
/// of its own is a rule's refusal, so the counters count it blocked, exactly
/// as Activity lists it, and never as an error.
#[tokio::test]
async fn p1e_a_grant_refusal_is_blocked_on_the_counters_and_in_activity() {
    let endpoint = Endpoint::start(false).await;
    let rig = rig(&endpoint, AuditFailurePolicy::BestEffort, false, false).await;
    let store = Arc::new(crate::counters::CounterStore::new(
        crate::clock::unix_secs().expect("a readable clock"),
    ));
    rig.state.meta_mcp.set_counters(Arc::clone(&store));

    let invoke = json!({"server": CAPS, "tool": PERSONAL, "arguments": {}});
    let answer = mcp_call(&rig, "gateway_invoke", &invoke).await;
    let held = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(
        held[0]["invocation_recorded"],
        json!(false),
        "premise: {answer}"
    );

    let [_, blocks, errors, _, _] = crate::counters::test_totals::totals(&store);
    let outcomes: Vec<Value> = activity(&rig, "")
        .await
        .iter()
        .map(|row| row["outcome"].clone())
        .collect();
    assert!(
        (blocks, errors) == (1, 0) && outcomes == [json!("blocked")],
        "(e) grant refusal: should be blocked; counters blocks={blocks} errors={errors}; \
         activity {outcomes:?}"
    );
}

fn stepped_playbook(steps: usize) -> crate::playbook::PlaybookEngine {
    let mut engine = crate::playbook::PlaybookEngine::new();
    let step = format!("  - name: read\n    server: {CAPS}\n    tool: {PERSONAL}\n");
    engine.register(
        crate::yaml::from_str(&format!(
            "name: stepped\ndescription: personal steps\non_error: abort\nsteps:\n{}",
            step.repeat(steps)
        ))
        .expect("the playbook parses"),
    );
    engine
}

/// Two steps on one (server, tool): the route stage ends the request at the
/// first refused step (`route_stage.rs`, the `index >= request_targets`
/// return), so one request writes one refusal record, one decision and one
/// row, never one record covering a second refusal.
#[tokio::test]
async fn two_refused_steps_on_one_target_end_the_request_at_the_first() {
    let endpoint = Endpoint::start(false).await;
    let rig = rig(&endpoint, AuditFailurePolicy::BestEffort, false, false).await;
    rig.state.meta_mcp.set_playbook_engine(stepped_playbook(2));

    let answer = mcp_call(&rig, "gateway_run_playbook", &json!({ "name": "stepped" })).await;

    assert!(
        answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true)),
        "premise: the steps are refused: {answer}"
    );
    let held = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(held.len(), 1, "one refusal, one decision: {held:#?}");
    assert_eq!(
        invocations(&rig.dir).len(),
        1,
        "one refusal record: {answer}"
    );
    assert_eq!(activity(&rig, "").await.len(), 1, "one row");
}

/// A route-stage refusal whose invocation append fails marks nothing: its
/// decision stays unrecorded, and Activity lists the one blocked row.
#[tokio::test]
async fn a_failed_refusal_append_leaves_its_decision_unrecorded_and_listed() {
    let endpoint = Endpoint::start(false).await;
    let rig = rig(&endpoint, AuditFailurePolicy::BestEffort, false, false).await;
    rig.state.meta_mcp.set_playbook_engine(stepped_playbook(1));
    let log = rig.state.transparency_log.as_ref().expect("the rig logs");
    // The refusal's invocation record is the first of route `meta`.
    log.fail_next_append_of_kind_for_test("meta");

    let answer = mcp_call(&rig, "gateway_run_playbook", &json!({ "name": "stepped" })).await;

    assert!(
        answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true)),
        "premise: the step is refused: {answer}"
    );
    let held = wait_for_decisions(&rig.dir, 1).await;
    assert_eq!(held[0]["invocation_recorded"], json!(false), "{held:#?}");
    assert!(
        invocations(&rig.dir).is_empty(),
        "the append failed: {answer}"
    );
    let rows = activity(&rig, "").await;
    assert_eq!(rows.len(), 1, "{rows:#?}");
    assert_eq!(rows[0]["outcome"], json!("blocked"), "{rows:#?}");
}
