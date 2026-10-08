// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7215.CONTROL.5, gap G4: the projection A/B arm and the prefetch hints
//! key on the caller, never on the empty id every modern caller shares.
//!
//! Every row drives the router with a modern `tools/call`: no session header,
//! so the session id the meta route sees is "". A keyless modern caller gets
//! no arm of its own and no hints.

use axum::body::to_bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

use super::issue_555_listing_scope::{Auth, fixture_with, key};
use crate::projection::ProjectionMode;
use crate::transition::TransitionTracker;

const MODERN: &str = "2026-07-28";

/// One modern `tools/call` as `bearer` (anonymous when `None`).
async fn modern(router: &axum::Router, bearer: Option<&str>, name: &str, args: Value) -> Value {
    let params = json!({
        "name": name,
        "arguments": args,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "g4", "version": "1.0.0" },
        },
    });
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", "tools/call")
        .header("mcp-name", name);
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let body = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params });
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// One legacy `tools/call` on `session` (a new one when `None`).
async fn legacy(
    router: &axum::Router,
    session: Option<&str>,
    name: &str,
    args: Value,
) -> (Option<String>, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let body = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": { "name": name, "arguments": args } });
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        session,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn invoke(server: &str, tool: &str) -> Value {
    json!({ "server": server, "tool": tool, "arguments": { "q": "x" } })
}

fn delivered(body: &Value) -> &Value {
    assert!(
        body.get("error").is_none() && !body["result"].is_null(),
        "call must be delivered: {body}"
    );
    body
}

/// Whether the response carries prediction hints at all.
fn has_hints(body: &Value) -> bool {
    body.to_string().contains("predicted_next")
}

/// The `predicted_next` hints anywhere in the response, as text: the tool
/// result travels as JSON inside a text block, so string leaves are parsed too.
fn hints(body: &Value) -> String {
    match body {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                if k == "predicted_next" {
                    v.to_string()
                } else {
                    hints(v)
                }
            })
            .collect(),
        Value::Array(items) => items.iter().map(hints).collect(),
        Value::String(text) => serde_json::from_str::<Value>(text)
            .map(|inner| hints(&inner))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Whether the response carries a hint naming `beta_tool`.
fn hints_beta(body: &Value) -> bool {
    has_hints(body) && body.to_string().contains("beta_tool")
}

// ── row 18: prefetch hints ───────────────────────────────────────────────────

#[tokio::test]
async fn r1_one_callers_tool_is_never_another_callers_predecessor() {
    let f = fixture_with(Auth::Keys, |meta| meta).await;
    f.state
        .meta_mcp
        .set_transition_tracker(Arc::new(TransitionTracker::new()));
    for _ in 0..3 {
        let a = modern(
            &f.router,
            Some("open-key"),
            "gateway_invoke",
            invoke("alpha", "alpha_read"),
        )
        .await;
        delivered(&a);
        let b = modern(
            &f.router,
            Some("u2"),
            "gateway_invoke",
            invoke("beta", "beta_tool"),
        )
        .await;
        delivered(&b);
    }
    let last = modern(
        &f.router,
        Some("open-key"),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        !hints_beta(delivered(&last)),
        "u2's beta_tool was learned as open-key's successor: {last}"
    );
    // Its own history: alpha_read after alpha_read, three times.
    assert!(
        hints(&last).contains("alpha_read"),
        "open-key's own sequence is not predicted: {last}"
    );
}

#[tokio::test]
async fn r2_a_keyless_modern_caller_gets_no_hints_and_records_nothing() {
    let f = fixture_with(Auth::Off, |meta| meta).await;
    let tracker = Arc::new(TransitionTracker::new());
    f.state
        .meta_mcp
        .set_transition_tracker(Arc::clone(&tracker));
    for _ in 0..3 {
        delivered(
            &modern(
                &f.router,
                None,
                "gateway_invoke",
                invoke("alpha", "alpha_read"),
            )
            .await,
        );
        delivered(
            &modern(
                &f.router,
                None,
                "gateway_invoke",
                invoke("beta", "beta_tool"),
            )
            .await,
        );
    }
    let last = modern(
        &f.router,
        None,
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        !has_hints(delivered(&last)),
        "a keyless caller was served hints: {last}"
    );
    assert_eq!(
        tracker.total_transitions(),
        0,
        "a keyless caller's calls were recorded"
    );
}

#[tokio::test]
async fn guard_a_keyed_caller_still_gets_hints_from_its_own_sequence() {
    let f = fixture_with(Auth::Keys, |meta| meta).await;
    f.state
        .meta_mcp
        .set_transition_tracker(Arc::new(TransitionTracker::new()));
    for _ in 0..3 {
        delivered(
            &modern(
                &f.router,
                Some("open-key"),
                "gateway_invoke",
                invoke("alpha", "alpha_read"),
            )
            .await,
        );
        delivered(
            &modern(
                &f.router,
                Some("open-key"),
                "gateway_invoke",
                invoke("beta", "beta_tool"),
            )
            .await,
        );
    }
    let last = modern(
        &f.router,
        Some("open-key"),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        hints_beta(delivered(&last)),
        "own sequence not predicted: {last}"
    );
}

#[tokio::test]
async fn r6_a_keyless_legacy_session_gets_no_hints() {
    // MIK-7997: a session id never stands in for a missing caller key.
    let f = fixture_with(Auth::Off, |meta| meta).await;
    f.state
        .meta_mcp
        .set_transition_tracker(Arc::new(TransitionTracker::new()));
    let mut session = None;
    for _ in 0..3 {
        for (server, tool) in [("alpha", "alpha_read"), ("beta", "beta_tool")] {
            let (sid, body) = legacy(
                &f.router,
                session.as_deref(),
                "gateway_invoke",
                invoke(server, tool),
            )
            .await;
            delivered(&body);
            session = session.or(sid);
        }
    }
    assert!(session.is_some(), "a legacy call is given a session");
    let (_, last) = legacy(
        &f.router,
        session.as_deref(),
        "gateway_invoke",
        invoke("alpha", "alpha_read"),
    )
    .await;
    assert!(
        !has_hints(delivered(&last)),
        "a keyless legacy session got hints: {last}"
    );
}

// ── row 16: projection A/B arm ───────────────────────────────────────────────

/// The capability backend the arm rows call.
pub(in crate::gateway::router::tests) const PROJ_CAPS: &str = "proj_caps";
/// A public capability with a projection spec, served by a loopback endpoint.
pub(in crate::gateway::router::tests) const PROJ_DAY: &str = "proj_day";

pub(in crate::gateway::router::tests) fn projected_capability(
    port: u16,
) -> Arc<crate::capability::CapabilityBackend> {
    let definition = crate::capability::parse_capability(&format!(
        "name: {PROJ_DAY}\n\
         description: Read one day\n\
         metadata:\n\
         \x20 exposure: public\n\
         \x20 read_only: true\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://localhost:{port}\n\
         \x20     path: /read\n\
         \x20     method: GET\n\
         projection:\n\
         \x20 subject:\n\
         \x20   id: day\n"
    ))
    .expect("the capability parses");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client");
    let executor =
        Arc::new(crate::capability::CapabilityExecutor::new().with_test_http_client(client));
    let backend = Arc::new(crate::capability::CapabilityBackend::new(
        PROJ_CAPS, executor,
    ));
    backend
        .register_capability(definition)
        .expect("the capability registers");
    backend
}

/// A projected result carries `_raw`; a raw one does not.
fn projected(body: &Value) -> bool {
    delivered(body).to_string().contains("_raw")
}

async fn arm_fixture(
    auth: Auth,
    mode: ProjectionMode,
) -> (
    super::issue_555_listing_scope::Fixture,
    crate::gateway::meta_mcp::grant_audit_fixture::Endpoint,
) {
    let endpoint = crate::gateway::meta_mcp::grant_audit_fixture::Endpoint::start(false).await;
    let f = fixture_with(auth, |meta| meta.with_projection_mode(mode)).await;
    f.state
        .meta_mcp
        .set_capabilities(projected_capability(endpoint.port));
    (f, endpoint)
}

#[tokio::test]
async fn guard_the_capability_is_projected_when_projection_is_on() {
    let (f, _endpoint) = arm_fixture(Auth::Keys, ProjectionMode::On).await;
    let body = modern(
        &f.router,
        Some("open-key"),
        "gateway_invoke",
        invoke(PROJ_CAPS, PROJ_DAY),
    )
    .await;
    assert!(projected(&body), "fixture spec does not project: {body}");
}

#[tokio::test]
async fn r3_two_caller_keys_get_their_own_arms() {
    // Offline: "credential:12:" + sha256(name)[..12] puts open-key in
    // control and u2 in treatment; "" is treatment.
    let (f, _endpoint) = arm_fixture(Auth::Keys, ProjectionMode::Experimental).await;
    for round in 0..2 {
        let control = modern(
            &f.router,
            Some("open-key"),
            "gateway_invoke",
            invoke(PROJ_CAPS, PROJ_DAY),
        )
        .await;
        assert!(
            !projected(&control),
            "round {round}: open-key shares another arm: {control}"
        );
        let treatment = modern(
            &f.router,
            Some("u2"),
            "gateway_invoke",
            invoke(PROJ_CAPS, PROJ_DAY),
        )
        .await;
        assert!(
            projected(&treatment),
            "round {round}: u2 lost its arm: {treatment}"
        );
    }
}

#[tokio::test]
async fn r4_a_keyless_modern_caller_gets_the_control_shape() {
    let (f, _endpoint) = arm_fixture(Auth::Off, ProjectionMode::Experimental).await;
    let body = modern(
        &f.router,
        None,
        "gateway_invoke",
        invoke(PROJ_CAPS, PROJ_DAY),
    )
    .await;
    assert!(
        !projected(&body),
        "a keyless caller was put in an arm: {body}"
    );
}

#[test]
fn r5_a_keyless_call_is_not_in_the_experiment() {
    assert_eq!(
        crate::projection::ab_classification(ProjectionMode::Experimental, None, false, true),
        None
    );
}

// ── reclaim: the router tracks the caller key without a firewall ─────────────

#[tokio::test]
async fn r7_a_keyed_modern_call_is_tracked_for_idle_reclaim() {
    let config = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![key("open-key", &["*"])],
        ..Default::default()
    };
    let (mut state, _store) = super::test_router_app_state_with_auth(&config).await;
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .session_lifecycle = Some(Arc::clone(&lifecycle));
    let router = super::create_router(state);
    let body = modern(
        &router,
        Some("open-key"),
        "gateway_search_tools",
        json!({ "query": "x" }),
    )
    .await;
    assert!(body.get("error").is_none(), "search must answer: {body}");
    assert_eq!(
        lifecycle.tracked_count(),
        1,
        "the caller key has no reclaim deadline"
    );
}

/// How many A/B events one `gateway_invoke` of the projected capability emits
/// as `bearer`, read from a real tracing subscriber.
fn ab_events(auth: Auth, bearer: Option<&'static str>) -> usize {
    let records = crate::test_log_capture::records(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let (f, _endpoint) = arm_fixture(auth, ProjectionMode::Experimental).await;
                let body = modern(
                    &f.router,
                    bearer,
                    "gateway_invoke",
                    invoke(PROJ_CAPS, PROJ_DAY),
                )
                .await;
                delivered(&body);
            });
    });
    crate::test_log_capture::count(&records, "INFO", "projection A/B invocation")
}

#[test]
fn r4b_a_keyless_call_emits_no_ab_event() {
    // Not vacuous: a keyed caller's call is in the experiment and is logged.
    assert_eq!(
        ab_events(Auth::Keys, Some("u2")),
        1,
        "the capture sees no A/B event"
    );
    assert_eq!(
        ab_events(Auth::Off, None),
        0,
        "a keyless call was counted in an arm"
    );
}
