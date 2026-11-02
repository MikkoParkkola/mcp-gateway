// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user backend hidden from the caller, judged against the listing and
//! the caller's own slot.
//!
//! The listing judges a per-user backend by its shared slot alone. A backend
//! it leaves out is hidden, and answers as an unregistered name, only when
//! the caller's own slot is held and refuses the call too: a slot that admits
//! keeps the call, and a cold one proves nothing, so a caller is never
//! refused what it could call before. A caller with no view of the backend
//! (no binding that could ever fill) is hidden. The listing gap that remains
//! (the listing ignores the caller's own slot) is tracked separately.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{Gateway, gateway_on};
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, BINDING, CallerSlot, Warmth, arm_alpha_upstream, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

/// A tool only alpha's own slot holds; the shared slot never lists it.
const OWN_TOOL: &str = "own_note";

fn alpha() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

fn cert() -> crate::mtls::CertIdentity {
    crate::mtls::CertIdentity {
        common_name: Some("agent".to_string()),
        display_name: "agent".to_string(),
        ..Default::default()
    }
}

/// The per-user gateway in `warmth`, under an mTLS rule that allows only
/// [`OWN_TOOL`]: every tool the shared slot lists is refused, so the listing
/// leaves the backend out. Warm, alpha's own slot also holds [`OWN_TOOL`].
async fn gateway(warmth: Warmth) -> Gateway {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let (mut state, store) =
        super::direct_route_state_with_identity(crate::config::AgentIdentityConfig::default())
            .await;
    Arc::get_mut(&mut state)
        .expect("state is unique")
        .mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![PolicyRuleConfig {
            match_criteria: CertMatchConfig {
                cn: Some("agent".to_string()),
                ..Default::default()
            },
            allow: ToolScopeConfig {
                backends: vec!["*".to_string()],
                tools: vec![OWN_TOOL.to_string()],
            },
            deny: ToolScopeConfig::default(),
        }],
        ..Default::default()
    }));
    let gw = gateway_on(
        (state, store),
        (CallerSlot::Valid, &valid(), warmth),
        ("other", false),
        |_| {},
    );
    if warmth == Warmth::Warm {
        let tools: Vec<crate::protocol::Tool> = serde_json::from_value(json!([
            {"name": "note", "inputSchema": valid()},
            {"name": "read", "inputSchema": valid()},
            {"name": OWN_TOOL, "inputSchema": valid()},
        ]))
        .expect("tools");
        gw.backend.store_per_user_tools_for_test(BINDING, tools);
    }
    gw
}

/// `tools/call` of `params` on `/mcp` with the `agent` certificate, as alpha
/// when `identified`.
async fn send(gw: &Gateway, params: Value, identified: bool) -> (u16, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    request.extensions_mut().insert(cert());
    if identified {
        request.extensions_mut().insert(alpha());
    }
    let response = gw.router.clone().oneshot(request).await.expect("response");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Whether `gateway_list_servers` names the per-user backend.
async fn listed(gw: &Gateway, identified: bool) -> bool {
    let (_, body) = send(
        gw,
        json!({"name": "gateway_list_servers", "arguments": {}}),
        identified,
    )
    .await;
    body.to_string().contains(&format!("\"{BACKEND}\""))
}

/// The hiding judgment for the `agent` certificate, as alpha when `identified`.
fn hides(gw: &Gateway, identified: bool) -> bool {
    crate::gateway::router::caller_hiding::RouterHiding::caller(
        Arc::clone(&gw.state),
        crate::gateway::router::OwnedRouterAuthorizer::capture(None, None, Some(&cert())),
        identified.then(alpha),
        None,
    )
    .hides(BACKEND)
}

/// The exception: the listing leaves the backend out (its shared slot refuses
/// every tool), yet alpha's own slot admits [`OWN_TOOL`], so it is not hidden.
#[tokio::test]
async fn a_caller_whose_own_slot_admits_is_not_hidden_though_unlisted() {
    let gw = gateway(Warmth::Warm).await;
    assert!(!listed(&gw, true).await, "the listing named the backend");
    assert!(!hides(&gw, true), "a caller its own slot admits was hidden");
}

/// Cold: alpha's slot is not held, so it proves no refusal, and the backend
/// the listing leaves out is not hidden: hiding it would refuse the first
/// call, which then never fills the slot.
#[tokio::test]
async fn a_cold_caller_slot_does_not_hide_an_unlisted_backend() {
    let gw = gateway(Warmth::Cold).await;
    assert!(!listed(&gw, true).await, "the listing named the backend");
    assert!(!hides(&gw, true), "a cold caller slot hid the backend");
}

/// Guard: with a cold slot, the caller's first call still reaches the
/// backend, which fills the slot.
#[tokio::test]
async fn a_cold_caller_slot_first_call_reaches_the_backend() {
    let gw = gateway(Warmth::Cold).await;
    let upstream = arm_alpha_upstream(&gw.backend, &["note", "read", OWN_TOOL]);
    let (status, body) = send(
        &gw,
        json!({"name": "gateway_invoke",
               "arguments": {"server": BACKEND, "tool": OWN_TOOL, "arguments": {"q": "x"}}}),
        true,
    )
    .await;
    let text = body.to_string();
    assert_eq!(status, 200, "{text}");
    for absent in [
        "Backend not found",
        "lacks scope",
        "blocked by certificate policy",
    ] {
        assert!(
            !text.contains(absent),
            "the first call was refused ({absent}): {text}"
        );
    }
    assert!(
        upstream.calls() > 0,
        "the first call never reached the backend: {text}"
    );
}

/// No view: a caller with no principal on this required backend has no slot,
/// so its own slot never admits, and the unlisted backend is hidden.
#[tokio::test]
async fn a_caller_with_no_view_is_hidden_from_an_unlisted_backend() {
    let gw = gateway(Warmth::Warm).await;
    assert!(!listed(&gw, false).await, "the listing named the backend");
    assert!(hides(&gw, false), "a caller with no view was not hidden");
}

/// Guard: a call that worked before still works. Alpha's own slot admits
/// [`OWN_TOOL`], so its call reaches the backend, not an absent-name answer.
#[tokio::test]
async fn a_caller_whose_own_slot_admits_still_calls() {
    let gw = gateway(Warmth::Warm).await;
    let (status, body) = send(
        &gw,
        json!({"name": "gateway_invoke",
               "arguments": {"server": BACKEND, "tool": OWN_TOOL, "arguments": {"q": "x"}}}),
        true,
    )
    .await;
    let text = body.to_string();
    assert_eq!(status, 200, "{text}");
    for absent in [
        "Backend not found",
        "does not list a tool",
        "lacks scope",
        "blocked by certificate policy",
    ] {
        assert!(
            !text.contains(absent),
            "the call was refused ({absent}): {text}"
        );
    }
    assert!(
        gw.dispatched() > 0,
        "the call never reached the backend: {text}"
    );
}
