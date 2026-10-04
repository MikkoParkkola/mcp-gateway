// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Origin and Host validation, and the admin meta-tool gate.

use super::*;
use pretty_assertions::assert_eq;

// ── Origin / Host validation (CWE-346) ────────────────────────────────────────
//
// The gateway binds loopback and, with auth off, treats every caller as an
// anonymous identity. A web page can therefore reach `/mcp` either by rebinding
// a hostname to 127.0.0.1 or, because the handler never checks Content-Type, by
// a preflight-free cross-origin POST. A browser always sends `Origin`; a CLI MCP
// client never does. That asymmetry is the gate.

fn mcp_request_with(header: Option<(&str, &str)>) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn mcp_rejects_foreign_origin() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let response = router
        .oneshot(mcp_request_with(Some((
            "origin",
            "http://attacker.example",
        ))))
        .await
        .unwrap();
    // Must fail on the gate, not on a parse error: the body above is valid.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_allows_absent_origin() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let response = router.oneshot(mcp_request_with(None)).await.unwrap();
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a CLI MCP client sends no Origin and must keep working"
    );
}

#[tokio::test]
async fn mcp_allows_bind_origin() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let response = router
        .oneshot(mcp_request_with(Some(("origin", "http://127.0.0.1:39400"))))
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_rejects_foreign_host() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    // No Origin at all: this is the rebinding shape, where the browser's own
    // Origin may be suppressed but Host carries the attacker's name.
    let response = router
        .oneshot(mcp_request_with(Some(("host", "attacker.example"))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn anonymous_denied_admin_meta_tools() {
    use super::authorization::{ADMIN_META_TOOLS, require_admin_tool_access};
    let anon = crate::gateway::auth::anonymous_client();

    // Iterates the one list rather than a copy of it. The copy had drifted:
    // it still named two tools removed from the admin set, and the assertion
    // did not notice because `require_admin_tool_access` never reads the tool
    // name — it answers from the client's admin bit alone, so the loop asserted
    // the same thing once per entry whatever the entries were.
    for tool in ADMIN_META_TOOLS {
        assert!(
            super::authorization::is_admin_meta_tool(tool),
            "{tool} is in the admin list, so the predicate must say so"
        );
        assert!(
            require_admin_tool_access(None, Some(&anon), None, tool)
                .await
                .is_err(),
            "anonymous must not reach {tool}"
        );
    }

    for session_local in ["gateway_set_profile", "gateway_set_state"] {
        assert!(
            !super::authorization::is_admin_meta_tool(session_local),
            "{session_local} writes only the caller's own session and must stay \
             out of the admin list"
        );
    }
}

#[tokio::test]
async fn mcp_rejects_no_cors_get_from_a_page() {
    // The Fetch standard omits `Origin` from a no-CORS GET, so the
    // absent-Origin allowance would admit it. Fetch Metadata is what catches it.
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("sec-fetch-site", "cross-site")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_rejects_opaque_origin() {
    // A sandboxed iframe and a cross-site redirect both send `Origin: null`.
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let response = router
        .oneshot(mcp_request_with(Some(("origin", "null"))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_allows_same_origin_browser_request() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:39400")
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_rejects_foreign_authority_without_host_header() {
    // HTTP/2 carries the target in the `:authority` pseudo-header, not `Host`,
    // so a gate that reads only `Host` is inert over HTTP/2 and the rebinding
    // refusal disappears on exactly the protocol browsers prefer.
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("http://attacker.example/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    assert!(
        request.headers().get(axum::http::header::HOST).is_none(),
        "the case is only meaningful with no Host header present"
    );
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Build router state whose live config binds a wildcard address.
async fn wildcard_bind_app_state() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store_dir) = test_router_app_state().await;
    let mut config = crate::config::Config::default();
    config.server.host = "0.0.0.0".to_string();
    state.live_config.set(config);
    (state, store_dir)
}

#[tokio::test]
async fn wildcard_bind_refuses_a_rebound_name_through_the_middleware() {
    // The policy unit tests assert the rule; this asserts the middleware
    // actually applies it on the real route, so the wildcard allowance cannot
    // widen back into a rebinding path during a refactor.
    let (state, _store) = wildcard_bind_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "attacker.example")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wildcard_bind_admits_a_numeric_host_through_the_middleware() {
    let (state, _store) = wildcard_bind_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "192.168.1.5:39400")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn merged_routes_are_behind_the_origin_gate() {
    // Routes merged after the layer stack would skip the gate entirely. That
    // set includes the key server's token exchange and revocation endpoints,
    // JWKS, the protected-resource metadata, /metrics and the UI HTML.
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    for uri in [
        "/.well-known/jwks.json",
        "/.well-known/oauth-protected-resource",
        "/metrics",
    ] {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("origin", "http://attacker.example")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} must be refused for a cross-site Origin"
        );
    }
}

#[tokio::test]
async fn a_route_merged_after_create_router_is_still_gated() {
    // Round 4 fixed merges INSIDE create_router; a merge OUTSIDE it reopened
    // the same hole for the webhook routes. The guard is therefore applied to
    // extra routes handed in, not to whatever happened to be merged by then.
    let extra = axum::Router::new().route(
        "/webhooks/test",
        axum::routing::post(|| async { axum::http::StatusCode::OK }),
    );
    let (state, _store) = test_router_app_state().await;
    let router = create_router_with(state, Some(extra));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/webhooks/test")
        .header("origin", "http://attacker.example")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_numeric_origin_must_match_the_request_authority() {
    // Round 6 admitted ANY numeric Origin on a non-loopback bind, reasoning
    // that a browser sets Origin from where the page came so an attacker
    // cannot claim one. An attacker can: host the page on a public IP and the
    // browser sends that address as the Origin. It is only safe when it names
    // the gateway the request is actually addressed to.
    let (state, _store) = wildcard_bind_app_state().await;
    let router = create_router(state);

    let attacker = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "192.168.1.5:39400")
        .header("origin", "http://203.0.113.5")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(attacker).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a numeric Origin naming another host must be refused"
    );

    let own_page = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "192.168.1.5:39400")
        .header("origin", "http://192.168.1.5:39400")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    assert_ne!(
        router.oneshot(own_page).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "the gateway's own page must still work"
    );
}

/// The admin gate covers the tools with global effect, and only those.
///
/// Both halves matter. Gating too little leaves a shared control open to any
/// caller; gating too much breaks a legitimate workflow while stopping nothing,
/// which is what happened to `gateway_set_profile`: it was announced as
/// admin-only in the changelog, was never tested, and was bypassable anyway
/// because `handle_initialize` binds a caller-supplied profile through the
/// identical call with no credential.
#[test]
fn admin_gate_covers_global_tools_and_not_session_local_ones() {
    for global in [
        "gateway_kill_server",
        "gateway_revive_server",
        "gateway_reload_config",
        "gateway_reload_capabilities",
    ] {
        assert!(
            super::authorization::is_admin_meta_tool(global),
            "{global} changes the gateway for every session and must need a credential"
        );
    }

    for session_local in ["gateway_set_profile", "gateway_set_state"] {
        assert!(
            !super::authorization::is_admin_meta_tool(session_local),
            "{session_local} writes only the caller's own session and cannot widen \
             what that caller reaches, so gating it blocks the documented path \
             while leaving the equivalent one at initialize open"
        );
    }
}

/// A non-admin caller can switch its own routing profile.
///
/// The regression guard for the half above that is easy to re-break: someone
/// reading `set_profile` as "administrative" and adding it back to the gate.
#[tokio::test]
async fn non_admin_may_set_its_own_routing_profile() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .header("mcp-session-id", "sess-profile")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "gateway_set_profile",
                    "arguments": { "profile": "does-not-exist" }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    // The profile name is deliberately unknown: the assertion is about the
    // GATE, not about profile resolution. A refusal for lacking admin is what
    // must not happen; being told the profile is unknown means the call got
    // past the gate and reached the tool.
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a non-admin must not be refused its own session's routing profile"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("admin access"),
        "and must not be told it needs admin: {message}"
    );
}
