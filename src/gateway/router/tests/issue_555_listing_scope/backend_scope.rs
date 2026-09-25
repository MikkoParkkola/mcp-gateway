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
use super::{Auth, Fixture, call_tool, fixture, rpc};
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
        agent_id: None,
        grant_subject: None,
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
