// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Calls refused by an identity grant, through `/mcp`, read back through the
//! Activity route: a refusal with no invocation record of its own is one
//! blocked row, and a call with an invocation record is one row. Every row
//! asserts the raw record counts first.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::meta_fixture::test_router_app_state_with_logs;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend, grants, invocations, logger, wait_for_decisions,
};
use crate::gateway::routes;
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
    let dir = Arc::new(tempfile::tempdir().unwrap());
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
    let request = Request::builder()
        .method("GET")
        .uri(format!("{}?limit=200{query}", routes::UI_ACTIVITY))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))))
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
        .body(Body::empty())
        .unwrap();
    let router = create_router(Arc::clone(&rig.state));
    let response = router.oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let page: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    page["rows"].as_array().cloned().unwrap_or_default()
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
