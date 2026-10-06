// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! GH1942.HARDEN.1 rows 8 and 16: under `security.posture: hardened` an HTTP
//! MCP request with no per-caller identity is refused with 403 before its body
//! is read, on every route; `standard` refuses nothing.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::hardened_identity::REFUSAL;
use super::tests::test_router_app_state_with_auth_and_config;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, ApiKeyKind, AuthConfig, Config};
use crate::security::SecurityPosture;

const SHARED: &str = "hardened-shared-key-0123456789";
const PERSONAL: &str = "hardened-personal-key-0123456789";
const BEARER: &str = "hardened-static-bearer-0123456789";

fn api_key(secret: &str, kind: ApiKeyKind) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: secret.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind,
    }
}

fn config(posture: SecurityPosture) -> Config {
    let mut config = Config::default();
    config.security.posture = posture;
    config
}

/// Auth on (a shared and a personal key) or off, under `posture`.
async fn gateway(posture: SecurityPosture, auth_on: bool) -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: auth_on,
        bearer_token: auth_on.then(|| BEARER.to_string()),
        api_keys: if auth_on {
            vec![
                api_key(SHARED, ApiKeyKind::Shared),
                api_key(PERSONAL, ApiKeyKind::Personal),
            ]
        } else {
            Vec::new()
        },
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_config(&auth, config(posture)).await
}

fn request(method: &str, uri: &str, bearer: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = match method {
        "POST" => builder.header("content-type", "application/json"),
        "GET" => builder.header("accept", "text/event-stream"),
        _ => builder,
    };
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    // A legacy `initialize` that declares elicitation: the one legacy request
    // row 10 serves without a session, so a refusal here is row 8's.
    let body = if method == "POST" {
        Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"elicitation": {}},
                "clientInfo": {"name": "hardened-identity-test", "version": "1"}
            }})
            .to_string(),
        )
    } else {
        Body::empty()
    };
    builder.body(body).unwrap()
}

/// The status, and the body only when refused (a served GET is an open stream).
async fn send(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, String) {
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    if status != StatusCode::FORBIDDEN {
        return (status, String::new());
    }
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn assert_refused((status, body): &(StatusCode, String), what: &str) {
    assert_eq!(*status, StatusCode::FORBIDDEN, "{what} was served: {body}");
    assert!(body.contains(REFUSAL), "{what}: another refusal: {body}");
    assert!(body.contains("-32600"), "{what}: wrong code: {body}");
}

fn assert_not_refused((status, body): &(StatusCode, String), what: &str) {
    assert!(
        !body.contains(REFUSAL),
        "{what} was refused: {status} {body}"
    );
}

#[tokio::test]
async fn hardened_refuses_without_subject_meta() {
    let (state, _store) = gateway(SecurityPosture::Hardened, true).await;
    for method in ["POST", "GET", "DELETE"] {
        let reply = send(&state, request(method, "/mcp", Some(SHARED))).await;
        assert_refused(&reply, &format!("{method} /mcp with a shared key"));
    }
    let reply = send(&state, request("POST", "/mcp", Some(BEARER))).await;
    assert_refused(&reply, "POST /mcp with the static bearer");
}

#[tokio::test]
async fn hardened_refuses_without_subject_direct() {
    let (state, _store) = gateway(SecurityPosture::Hardened, true).await;
    let reply = send(&state, request("POST", "/mcp/alpha", Some(SHARED))).await;
    assert_refused(&reply, "POST /mcp/alpha with a shared key");
}

#[tokio::test]
async fn hardened_refuses_an_anonymous_caller() {
    let (state, _store) = gateway(SecurityPosture::Hardened, false).await;
    let reply = send(&state, request("POST", "/mcp", None)).await;
    assert_refused(&reply, "an anonymous POST /mcp");
}

/// Row 8's "before its body is read", on both routes: the body fails as
/// soon as it is read, so a check that read it first would answer with that
/// failure instead of the identity refusal.
#[tokio::test]
async fn hardened_refuses_before_reading_the_body() {
    let (state, _store) = gateway(SecurityPosture::Hardened, true).await;
    for uri in ["/mcp", "/mcp/alpha"] {
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = Arc::clone(&polled);
        let unreadable = Body::from_stream(futures::stream::poll_fn(move |_| {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(Some(Err::<axum::body::Bytes, _>(std::io::Error::other(
                "the body was read",
            ))))
        }));
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {SHARED}"))
            .body(unreadable)
            .unwrap();
        let reply = send(&state, request).await;
        assert_refused(&reply, &format!("POST {uri} with an unreadable body"));
        assert!(
            !polled.load(std::sync::atomic::Ordering::SeqCst),
            "POST {uri}: the body was read before the refusal"
        );
    }
}

#[tokio::test]
async fn personal_api_key_is_identity() {
    let (state, _store) = gateway(SecurityPosture::Hardened, true).await;
    let reply = send(&state, request("POST", "/mcp", Some(PERSONAL))).await;
    assert_eq!(
        reply.0,
        StatusCode::OK,
        "a personal key on /mcp: {}",
        reply.1
    );
    let direct = send(&state, request("POST", "/mcp/alpha", Some(PERSONAL))).await;
    assert_not_refused(&direct, "a personal key on /mcp/alpha");
}

#[tokio::test]
async fn standard_posture_serves_a_shared_key() {
    let (state, _store) = gateway(SecurityPosture::Standard, true).await;
    let reply = send(&state, request("POST", "/mcp", Some(SHARED))).await;
    assert_eq!(
        reply.0,
        StatusCode::OK,
        "standard refused a shared key: {}",
        reply.1
    );
    let direct = send(&state, request("POST", "/mcp/alpha", Some(SHARED))).await;
    assert_not_refused(&direct, "standard on /mcp/alpha");
}

/// A signed agent JWT for `client_id`, registered in `registry`.
fn agent_token(registry: &crate::gateway::oauth::AgentRegistry, client_id: &str) -> String {
    let secret = format!("{client_id}-hardened-secret-0123456789");
    registry.register(crate::gateway::oauth::AgentDefinition {
        client_id: client_id.to_string(),
        name: client_id.to_string(),
        hs256_secret: Some(secret.clone()),
        rs256_public_key: None,
        scopes: vec![],
        issuer: None,
        audience: Some("hardened".to_string()),
    });
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({ "sub": client_id, "exp": now + 3600, "iat": now, "aud": "hardened" }),
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent token")
}

#[tokio::test]
async fn hardened_admits_a_proven_subject() {
    let (mut state, _store) = gateway(SecurityPosture::Hardened, false).await;
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let token = agent_token(&registry, "hardened-agent");
    Arc::get_mut(&mut state)
        .expect("no other state handle")
        .agent_auth = crate::gateway::oauth::AgentAuthState::new(true, registry);
    let reply = send(&state, request("POST", "/mcp", Some(&token))).await;
    assert_eq!(
        reply.0,
        StatusCode::OK,
        "a proven agent was refused: {}",
        reply.1
    );
}

#[cfg(feature = "webui")]
#[tokio::test]
async fn hardened_refuses_without_subject_dashboard() {
    use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
    let (state, _store) = gateway(SecurityPosture::Hardened, true).await;
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    let handle = state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits);
    let mut request = request("POST", "/mcp", None);
    request.headers_mut().insert(
        "cookie",
        format!("{SESSION_COOKIE}={handle}").parse().unwrap(),
    );
    let reply = send(&state, request).await;
    assert_refused(&reply, "a dashboard session on POST /mcp");
}
