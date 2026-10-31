// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A3 review follow-up: a backend *name* is disclosed only if the caller could
//! invoke something on it. Invocation also refuses on agent-auth scope and on
//! mTLS policy, so a backend those deny outright must not be named either.

use axum::body::to_bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

use super::meta_tools::payload;
use super::{Auth, Fixture, call_tool, fixture, post, rpc};
use crate::gateway::authz::ToolAuthorizer;
use crate::gateway::router::authorization::RouterAuthorizer;
use crate::gateway::test_helpers::CallerStanding;

/// The server names `gateway_list_servers` returns.
fn server_names(body: &Value) -> Vec<String> {
    payload(body)["servers"]
        .as_array()
        .unwrap_or_else(|| panic!("servers array: {body}"))
        .iter()
        .filter_map(|s| s["name"].as_str().map(str::to_string))
        .collect()
}

/// The fixture with agent auth switched on.
async fn with_agent_auth(registry: Arc<crate::gateway::oauth::AgentRegistry>) -> Fixture {
    let Fixture {
        router,
        mut state,
        store,
        caps,
    } = fixture(Auth::Off).await;
    drop(router);
    Arc::get_mut(&mut state).expect("router dropped").agent_auth =
        crate::gateway::oauth::AgentAuthState::new(true, registry);
    Fixture {
        router: super::create_router(Arc::clone(&state)),
        state,
        store,
        caps,
    }
}

/// T8b (i): agent auth on and no validated agent identity refuses every
/// backend tool, so no backend is admitted and none is counted.
#[tokio::test]
async fn agent_auth_without_identity_admits_no_backend() {
    let f = with_agent_auth(Arc::new(crate::gateway::oauth::AgentRegistry::new())).await;
    let authorizer = RouterAuthorizer {
        state: f.state.as_ref(),
        generation: &f.state.live_config.generation(),
        client: None,
        oauth_agent_identity: None,
        cert_identity: None,
        principal: None,
    };
    for server in ["alpha", "beta", "caps"] {
        assert!(
            !authorizer.admits_backend(server),
            "{server} admitted without an agent identity"
        );
    }
    let scope = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &authorizer,
        is_admin: false,
        api_key_name: None,
        grant_key: None,
        agent_id: None,
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::Anonymous,
    };
    let (_, servers) = f.state.meta_mcp.admitted_counts(scope, None);
    assert_eq!(
        servers, 0,
        "a backend was counted for a caller that can invoke nothing"
    );
    assert_eq!(CallerStanding::from(scope), CallerStanding::Standard);
}

/// T8b (ii): an agent whose scopes cover only `alpha` is not told `beta` or
/// the capability backend exist, on any surface that names backends.
#[tokio::test]
async fn agent_scoped_to_alpha_is_not_shown_other_backends() {
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token = super::direct_route::agent_token(&registry);
    let f = with_agent_auth(registry).await;
    let names =
        server_names(&call_tool(&f.router, Some(&token), "gateway_list_servers", json!({})).await);
    assert_eq!(
        names,
        ["alpha"],
        "list_servers named a backend the agent cannot invoke"
    );
    let init = rpc(&f.router, Some(&token), "initialize", super::guide::init()).await;
    let text = init["result"]["instructions"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        text.contains("across 1 backends"),
        "initialize counted other backends: {text}"
    );
    assert!(
        !text.contains("caps/"),
        "initialize guide named the capability backend: {text}"
    );
}

/// T8b (iii): an mTLS policy that denies every tool on `beta` for the
/// presented certificate hides `beta`'s name; `alpha` stays listed.
#[tokio::test]
async fn mtls_denied_backend_is_not_named() {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let Fixture {
        router,
        mut state,
        store: _store,
        caps: _caps,
    } = fixture(Auth::Off).await;
    drop(router);
    let rule = PolicyRuleConfig {
        match_criteria: CertMatchConfig {
            cn: Some("agent".to_string()),
            ..Default::default()
        },
        allow: ToolScopeConfig {
            backends: vec!["*".to_string()],
            tools: vec!["*".to_string()],
        },
        deny: ToolScopeConfig {
            backends: vec!["beta".to_string()],
            tools: Vec::new(),
        },
    };
    Arc::get_mut(&mut state)
        .expect("router dropped")
        .mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![rule],
        ..Default::default()
    }));
    let router = super::create_router(state);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "gateway_list_servers", "arguments": {} }
            })
            .to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(crate::mtls::CertIdentity {
        common_name: Some("agent".to_string()),
        display_name: "agent".to_string(),
        ..Default::default()
    });
    let response = router.oneshot(request).await.expect("router answers");
    let body: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("json");
    let names = server_names(&body);
    assert!(
        names.iter().any(|n| n == "alpha"),
        "control: alpha must stay listed: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "beta"),
        "mTLS-denied backend named: {names:?}"
    );
}

/// BACKENDGRANT.1: a key that lists no backends is refused on `tools/call`
/// before dispatch, by the backend rule and not a tool rule; the same call
/// with a `"*"` key is served, so the refusal is the grant and nothing else.
#[tokio::test]
async fn api_key_without_backends_is_forbidden_on_tools_call() {
    let f = fixture(Auth::Keys).await;
    let call = json!({ "name": "alpha_read", "arguments": {} });
    let (status, body) = post(
        &f.router,
        "/mcp/alpha",
        Some("bare-key"),
        "tools/call",
        call.clone(),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], json!(-32003), "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("no backends") && message.contains("UPGRADING-4.0.md section 32"),
        "the refusal names the empty grant and the upgrade note: {body}"
    );
    // The same refusal for a backend that does not exist: the message must not
    // tell a caller with no grant which backends are configured.
    let (status, absent) = post(
        &f.router,
        "/mcp/no-such-backend",
        Some("bare-key"),
        "tools/call",
        call.clone(),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{absent}");
    assert_eq!(absent["error"], body["error"], "existence leaked: {absent}");

    let (status, body) = post(
        &f.router,
        "/mcp/alpha",
        Some("open-key"),
        "tools/call",
        call,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "a \"*\" key is served: {body}");
}

/// A backend name the fixture never registers, beside the hidden `beta`.
const UNREGISTERED: &str = "gamma";

/// The fixture under an mTLS policy that denies every tool on `beta` for the
/// `agent` certificate, so `beta` is hidden from that caller. It denies the
/// unregistered name by the same rule: the policy treats both names alike, so
/// only registration could tell them apart.
async fn with_mtls_denying_beta() -> axum::Router {
    with_mtls((&["*"], &["*"]), (&["beta", UNREGISTERED], &[])).await
}

/// The fixture under one mTLS rule for the `agent` certificate: `allow` and
/// `deny` as (backends, tools).
async fn with_mtls(allow: (&[&str], &[&str]), deny: (&[&str], &[&str])) -> axum::Router {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let owned = |names: &[&str]| names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
    let Fixture {
        router, mut state, ..
    } = fixture(Auth::Off).await;
    drop(router);
    let rule = PolicyRuleConfig {
        match_criteria: CertMatchConfig {
            cn: Some("agent".to_string()),
            ..Default::default()
        },
        allow: ToolScopeConfig {
            backends: owned(allow.0),
            tools: owned(allow.1),
        },
        deny: ToolScopeConfig {
            backends: owned(deny.0),
            tools: owned(deny.1),
        },
    };
    Arc::get_mut(&mut state)
        .expect("router dropped")
        .mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![rule],
        ..Default::default()
    }));
    super::create_router(state)
}

/// `tools/call` of `params` on `uri`, presenting the `agent` certificate.
async fn post_as_agent_cert(router: &axum::Router, uri: &str, params: Value) -> (u16, String) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params })
                .to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(crate::mtls::CertIdentity {
        common_name: Some("agent".to_string()),
        display_name: "agent".to_string(),
        ..Default::default()
    });
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("router answers");
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The hidden backend's answer and the unregistered one's, the latter with
/// its name read as `beta`: a caller must not tell them apart.
fn assert_alike(route: &str, hidden: (u16, String), unregistered: (u16, String)) {
    // A trace id is minted per call, so it differs between any two calls.
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let hidden = (hidden.0, trace.replace_all(&hidden.1, "gw-ID").into_owned());
    let unregistered = (
        unregistered.0,
        trace
            .replace_all(&unregistered.1, "gw-ID")
            .replace(UNREGISTERED, "beta"),
    );
    assert_eq!(
        hidden, unregistered,
        "{route}: a hidden backend answers unlike an unregistered one"
    );
}

/// Under an mTLS policy hiding `beta`, `gateway_invoke` of its tool answers as
/// for a backend that is not registered.
#[tokio::test]
async fn mtls_hidden_backend_invokes_like_an_unregistered_one() {
    let router = with_mtls_denying_beta().await;
    let invoke = |server: &str| {
        json!({ "name": "gateway_invoke",
                "arguments": { "server": server, "tool": "beta_tool", "arguments": {} } })
    };
    let hidden = post_as_agent_cert(&router, "/mcp", invoke("beta")).await;
    let unregistered = post_as_agent_cert(&router, "/mcp", invoke(UNREGISTERED)).await;
    assert_alike("mtls gateway_invoke", hidden, unregistered);
}

/// The direct route answers the same two names alike under that policy.
#[tokio::test]
async fn mtls_hidden_backend_direct_route_answers_like_an_unregistered_one() {
    let router = with_mtls_denying_beta().await;
    let call = json!({ "name": "beta_tool", "arguments": {} });
    let hidden = post_as_agent_cert(&router, "/mcp/beta", call.clone()).await;
    let unregistered = post_as_agent_cert(&router, &format!("/mcp/{UNREGISTERED}"), call).await;
    assert_alike("mtls direct route", hidden, unregistered);
}

/// An agent scoped to `alpha` is not told `beta` exists: `gateway_invoke` of
/// its tool answers as for a backend that is not registered.
#[tokio::test]
async fn agent_hidden_backend_invokes_like_an_unregistered_one() {
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token = super::direct_route::agent_token(&registry);
    let f = with_agent_auth(registry).await;
    let invoke = |server: &str| {
        json!({ "name": "gateway_invoke",
                "arguments": { "server": server, "tool": "beta_tool", "arguments": {} } })
    };
    let ask = |params: Value| post(&f.router, "/mcp", Some(&token), "tools/call", params);
    let (hs, hb) = ask(invoke("beta")).await;
    let (us, ub) = ask(invoke(UNREGISTERED)).await;
    assert_alike(
        "agent gateway_invoke",
        (hs.as_u16(), hb.to_string()),
        (us.as_u16(), ub.to_string()),
    );
}

/// The direct route answers the same two names alike for that agent.
#[tokio::test]
async fn agent_hidden_backend_direct_route_answers_like_an_unregistered_one() {
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token = super::direct_route::agent_token(&registry);
    let f = with_agent_auth(registry).await;
    let call = json!({ "name": "beta_tool", "arguments": {} });
    let (hs, hb) = post(
        &f.router,
        "/mcp/beta",
        Some(&token),
        "tools/call",
        call.clone(),
    )
    .await;
    let (us, ub) = post(
        &f.router,
        &format!("/mcp/{UNREGISTERED}"),
        Some(&token),
        "tools/call",
        call,
    )
    .await;
    assert_alike(
        "agent direct route",
        (hs.as_u16(), hb.to_string()),
        (us.as_u16(), ub.to_string()),
    );
}

/// `gateway_invoke` of `tool` on `server`.
fn invoke(server: &str, tool: &str) -> Value {
    json!({ "name": "gateway_invoke",
            "arguments": { "server": server, "tool": tool, "arguments": {} } })
}

/// A tool name the policy permits but no backend lists: the hidden backend
/// must not answer it unlike an unregistered one (a permitted call reaches
/// later stages than a refused one).
#[tokio::test]
async fn mtls_permitted_unlisted_tool_on_a_hidden_backend_answers_like_an_unregistered_one() {
    // Only `ghost_tool` is allowed: no backend lists it, so every backend is
    // hidden from this certificate and the call itself is permitted.
    let router = with_mtls((&["*"], &["ghost_tool"]), (&[], &[])).await;
    let hidden = post_as_agent_cert(&router, "/mcp", invoke("beta", "ghost_tool")).await;
    let unregistered =
        post_as_agent_cert(&router, "/mcp", invoke(UNREGISTERED, "ghost_tool")).await;
    assert_alike("mtls permitted unlisted", hidden, unregistered);
}

/// The capability provider is a backend name like any other: an agent scoped
/// to `alpha` is not told `caps` exists.
#[tokio::test]
async fn agent_hidden_capability_provider_invokes_like_an_unregistered_one() {
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token = super::direct_route::agent_token(&registry);
    let f = with_agent_auth(registry).await;
    let ask = |params: Value| post(&f.router, "/mcp", Some(&token), "tools/call", params);
    let (hs, hb) = ask(invoke("caps", "cap_open")).await;
    let (us, ub) = ask(invoke(UNREGISTERED, "cap_open")).await;
    assert_alike(
        "agent hidden capability provider",
        (hs.as_u16(), hb.to_string()),
        (us.as_u16(), ub.to_string()),
    );
}

/// Control: a backend the certificate can see keeps today's answer for a tool
/// the policy refuses on it (the withheld path, answered as a missing tool).
#[tokio::test]
async fn mtls_visible_backend_refused_tool_keeps_its_answer() {
    let router = with_mtls((&["*"], &["*"]), (&[], &["alpha_write"])).await;
    let (status, body) = post_as_agent_cert(&router, "/mcp", invoke("alpha", "alpha_write")).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("the backend does not list a tool named `alpha_write`"),
        "a visible backend's refused tool changed its answer: {body}"
    );
}
