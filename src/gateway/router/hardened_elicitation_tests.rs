// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! GH1942.HARDEN.1 rows 10, 11 and 16: under `security.posture: hardened` a
//! legacy client must declare elicitation. Only an `initialize` that declares
//! it creates a legacy session on `/mcp`; the direct route, which keeps no
//! handshake state, serves no other legacy request; and a legacy destructive
//! call that nobody can confirm is refused. `standard` changes none of this.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_config;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, ApiKeyKind, AuthConfig, Config};
use crate::security::SecurityPosture;

/// The refusal a legacy client without elicitation gets under hardened.
const ELICITATION: &str = "client must declare elicitation (security.posture=hardened)";
/// A personal admin key: a per-caller identity (row 8) that may call
/// `gateway_kill_server`.
const OPERATOR: &str = "hardened-elicitation-operator-0123456789";
const MODERN: &str = "2026-07-28";

async fn gateway(posture: SecurityPosture) -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(OPERATOR.as_bytes())),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: ApiKeyKind::Personal,
        }],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let mut config = Config::default();
    config.security.posture = posture;
    config.server.modern_protocol = true;
    test_router_app_state_with_auth_and_config(&auth, config).await
}

struct Reply {
    status: StatusCode,
    session: Option<String>,
    body: String,
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> Reply {
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    // A served GET is an open stream: only a refusal has a body to read.
    let body = if status.is_success()
        && response
            .headers()
            .get("content-type")
            .is_some_and(|value| value.as_bytes().starts_with(b"text/event-stream"))
    {
        String::new()
    } else {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    Reply {
        status,
        session,
        body,
    }
}

/// A legacy POST: no `MCP-Protocol-Version`, optionally inside `session`.
fn legacy_post(uri: &str, body: &Value, session: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR}"));
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn initialize(capabilities: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": capabilities,
            "clientInfo": {"name": "hardened-elicitation-test", "version": "1"}
        }
    })
}

fn tools_list() -> Value {
    json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
}

fn tools_call(name: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

fn assert_elicitation_refused(reply: &Reply, what: &str) {
    assert_eq!(
        reply.status,
        StatusCode::FORBIDDEN,
        "{what} was not refused: {}",
        reply.body
    );
    assert!(
        reply.body.contains(ELICITATION),
        "{what}: another refusal: {}",
        reply.body
    );
    assert!(
        reply.body.contains("-32600"),
        "{what}: wrong code: {}",
        reply.body
    );
    assert!(reply.session.is_none(), "{what}: a session was minted");
}

fn assert_not_elicitation_refused(reply: &Reply, what: &str) {
    assert!(
        !reply.body.contains(ELICITATION),
        "{what} was refused: {} {}",
        reply.status,
        reply.body
    );
}

/// Row 10: a legacy `initialize` without elicitation is refused before any
/// session exists; one that declares it is served with a session.
#[tokio::test]
async fn hardened_refuses_legacy_without_elicitation_no_session() {
    let (state, _store) = gateway(SecurityPosture::Hardened).await;
    let before = state.multiplexer.session_count();
    for (capabilities, what) in [
        (json!({}), "no capabilities"),
        (json!({"sampling": {}}), "sampling only"),
        (json!({"elicitation": null}), "a null elicitation"),
    ] {
        let reply = send(
            &state,
            legacy_post("/mcp", &initialize(&capabilities), None),
        )
        .await;
        assert_elicitation_refused(&reply, &format!("initialize with {what}"));
    }
    assert_eq!(
        state.multiplexer.session_count(),
        before,
        "a refused initialize minted a session"
    );

    let reply = send(
        &state,
        legacy_post("/mcp", &initialize(&json!({"elicitation": {}})), None),
    )
    .await;
    assert_not_elicitation_refused(&reply, "initialize declaring elicitation");
    assert!(
        reply.session.is_some(),
        "a declaring initialize gets a session"
    );
}

/// Row 10: GET opens no legacy session under hardened; it only resumes one.
#[tokio::test]
async fn hardened_refuses_legacy_without_elicitation_get() {
    let (state, _store) = gateway(SecurityPosture::Hardened).await;
    let before = state.multiplexer.session_count();
    let get = || {
        Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("authorization", format!("Bearer {OPERATOR}"))
    };
    let reply = send(&state, get().body(Body::empty()).unwrap()).await;
    assert_elicitation_refused(&reply, "GET with no session");
    let reply = send(
        &state,
        get()
            .header("mcp-session-id", "gw-not-a-live-session")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_elicitation_refused(&reply, "GET naming no live session");
    assert_eq!(
        state.multiplexer.session_count(),
        before,
        "GET minted a session"
    );

    let session = send(
        &state,
        legacy_post("/mcp", &initialize(&json!({"elicitation": {}})), None),
    )
    .await
    .session
    .expect("a declaring initialize gets a session");
    let reply = send(
        &state,
        get()
            .header("mcp-session-id", session.as_str())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_not_elicitation_refused(&reply, "GET resuming a declared session");
    assert!(reply.status.is_success(), "GET resuming: {}", reply.status);
}

/// Row 10: a legacy request other than `initialize` mints nothing; inside a
/// session that a declaring `initialize` created, it is served.
#[tokio::test]
async fn hardened_legacy_request_without_session_refused() {
    let (state, _store) = gateway(SecurityPosture::Hardened).await;
    let before = state.multiplexer.session_count();
    let reply = send(&state, legacy_post("/mcp", &tools_list(), None)).await;
    assert_elicitation_refused(&reply, "tools/list with no session");
    let reply = send(
        &state,
        legacy_post("/mcp", &tools_list(), Some("gw-not-a-live-session")),
    )
    .await;
    assert_elicitation_refused(&reply, "tools/list naming no live session");
    assert_eq!(
        state.multiplexer.session_count(),
        before,
        "a refused request minted a session"
    );

    let session = send(
        &state,
        legacy_post("/mcp", &initialize(&json!({"elicitation": {}})), None),
    )
    .await
    .session
    .expect("a declaring initialize gets a session");
    let reply = send(&state, legacy_post("/mcp", &tools_list(), Some(&session))).await;
    assert_not_elicitation_refused(&reply, "tools/list inside a declared session");
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.body.contains("\"result\""),
        "no result: {}",
        reply.body
    );
}

/// Row 10: a modern request mints no session, so it cannot hand a legacy
/// request one to resume.
#[tokio::test]
async fn modern_request_mints_no_session_for_legacy_resume() {
    let (state, _store) = gateway(SecurityPosture::Hardened).await;
    let reply = send(&state, modern_post("/mcp", "tools/list", None, &json!({}))).await;
    assert!(reply.session.is_none(), "a modern request got a session");
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.body.contains("\"result\""),
        "no result: {}",
        reply.body
    );
    let reply = send(&state, legacy_post("/mcp", &tools_list(), None)).await;
    assert_elicitation_refused(&reply, "a legacy request after a modern one");
}

/// A well-formed 2026-07-28 request: header, mirrored method and name, and
/// the body metadata the revision requires.
fn modern_post(uri: &str, method: &str, name: Option<&str>, params: &Value) -> Request<Body> {
    let mut params = params.clone();
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR}"))
        .header("mcp-protocol-version", MODERN)
        .header("mcp-method", method);
    if let Some(name) = name {
        builder = builder.header("mcp-name", name);
    }
    let body = json!({"jsonrpc": "2.0", "id": 4, "method": method, "params": params});
    builder.body(Body::from(body.to_string())).unwrap()
}

/// The direct route was reached past the era gate: the request got as far as
/// the backend lookup, and this fixture has no backend called `alpha`.
fn assert_reached_backend_lookup(reply: &Reply, what: &str) {
    assert_not_elicitation_refused(reply, what);
    assert_eq!(
        reply.status,
        StatusCode::NOT_FOUND,
        "{what}: stopped before the backend lookup: {}",
        reply.body
    );
    assert!(
        reply.body.contains("Backend not found"),
        "{what}: {}",
        reply.body
    );
}

/// Refused by the shared request checks, before the backend lookup.
fn assert_refused_before_backend(reply: &Reply, what: &str) {
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "{what} was not refused: {}",
        reply.body
    );
    assert!(
        !reply.body.contains("Backend not found"),
        "{what}: {}",
        reply.body
    );
}

/// Row 10, direct route: no handshake state, so a legacy request other than a
/// declaring `initialize` is refused; a modern request is classified exactly as
/// on `/mcp`, so a modern header alone does not make a request modern.
#[tokio::test]
async fn hardened_direct_legacy_refused() {
    let (state, _store) = gateway(SecurityPosture::Hardened).await;
    let call = tools_call("echo", &json!({}));
    let reply = send(&state, legacy_post("/mcp/alpha", &call, None)).await;
    assert_elicitation_refused(&reply, "a direct legacy tools/call");
    let reply = send(
        &state,
        legacy_post("/mcp/alpha", &initialize(&json!({})), None),
    )
    .await;
    assert_elicitation_refused(&reply, "a direct legacy initialize without elicitation");

    let reply = send(
        &state,
        legacy_post("/mcp/alpha", &initialize(&json!({"elicitation": {}})), None),
    )
    .await;
    assert_reached_backend_lookup(&reply, "a direct initialize declaring elicitation");
    let arguments = json!({"name": "echo", "arguments": {}});
    let reply = send(
        &state,
        modern_post("/mcp/alpha", "tools/call", Some("echo"), &arguments),
    )
    .await;
    assert_reached_backend_lookup(&reply, "a well-formed modern tools/call");

    // A modern header over a legacy body: Malformed, not modern.
    let mut header_only = legacy_post("/mcp/alpha", &call, None);
    header_only
        .headers_mut()
        .insert("mcp-protocol-version", MODERN.parse().unwrap());
    header_only
        .headers_mut()
        .insert("mcp-method", "tools/call".parse().unwrap());
    header_only
        .headers_mut()
        .insert("mcp-name", "echo".parse().unwrap());
    let reply = send(&state, header_only).await;
    assert_refused_before_backend(&reply, "a modern header over a legacy body");

    let mut doubled = modern_post("/mcp/alpha", "tools/call", Some("echo"), &arguments);
    doubled
        .headers_mut()
        .append("mcp-name", "echo".parse().unwrap());
    let reply = send(&state, doubled).await;
    assert_refused_before_backend(&reply, "a doubled mcp-name header");

    let mut mismatched = modern_post("/mcp/alpha", "tools/call", Some("echo"), &arguments);
    mismatched
        .headers_mut()
        .insert("mcp-name", "other".parse().unwrap());
    let reply = send(&state, mismatched).await;
    assert_refused_before_backend(&reply, "an mcp-name header the body contradicts");

    let mut unsupported = modern_post("/mcp/alpha", "tools/call", Some("echo"), &arguments);
    unsupported
        .headers_mut()
        .insert("mcp-protocol-version", "2026-12-31".parse().unwrap());
    let body = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
        "name": "echo", "arguments": {},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-12-31",
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    }});
    *unsupported.body_mut() = Body::from(body.to_string());
    let reply = send(&state, unsupported).await;
    assert_refused_before_backend(&reply, "an unsupported modern revision");
}

/// Row 11: under hardened a legacy destructive call nobody can confirm is
/// refused; standard still proceeds with a warning.
#[tokio::test]
async fn hardened_legacy_confirmation_policy_refuses() {
    const REFUSED: &str = "Destructive action requires confirmation";
    for (posture, refused) in [
        (SecurityPosture::Hardened, true),
        (SecurityPosture::Standard, false),
    ] {
        let (state, _store) = gateway(posture).await;
        // Declared, so row 10 admits the session; no stream is open, so the
        // confirmation cannot reach anyone.
        let session = send(
            &state,
            legacy_post("/mcp", &initialize(&json!({"elicitation": {}})), None),
        )
        .await
        .session
        .expect("a declaring initialize gets a session");
        let kill = tools_call("gateway_kill_server", &json!({"server": "alpha"}));
        let reply = send(&state, legacy_post("/mcp", &kill, Some(&session))).await;
        assert_eq!(
            reply.body.contains(REFUSED),
            refused,
            "{posture:?}: {}",
            reply.body
        );
        let killed = state.meta_mcp.kill_switch().is_killed("alpha");
        if refused {
            assert!(reply.body.contains("-32001"), "{posture:?}: {}", reply.body);
            assert!(
                !killed,
                "{posture:?}: a refused call still killed the server"
            );
        } else {
            let body: Value = serde_json::from_str(&reply.body).expect("JSON-RPC body");
            assert!(body.get("error").is_none(), "{posture:?}: {body}");
            assert!(killed, "{posture:?}: the call proceeded but killed nothing");
        }
    }
}

/// Row 16: standard serves a legacy client that declares nothing, on both
/// routes, and lets it open a session without `initialize`.
#[tokio::test]
async fn standard_serves_legacy_without_elicitation() {
    let (state, _store) = gateway(SecurityPosture::Standard).await;
    let reply = send(&state, legacy_post("/mcp", &initialize(&json!({})), None)).await;
    assert_not_elicitation_refused(&reply, "standard initialize");
    assert!(
        reply.session.is_some(),
        "standard initialize gets a session"
    );
    let reply = send(&state, legacy_post("/mcp", &tools_list(), None)).await;
    assert_not_elicitation_refused(&reply, "standard tools/list with no session");
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.body.contains("\"result\""),
        "no result: {}",
        reply.body
    );
    let reply = send(
        &state,
        legacy_post("/mcp/alpha", &tools_call("echo", &json!({})), None),
    )
    .await;
    assert_reached_backend_lookup(&reply, "standard direct legacy tools/call");
}
