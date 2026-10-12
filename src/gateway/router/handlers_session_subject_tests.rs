// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! GH1942.HARDEN.1 row 9: a session belongs to (`CallerKey`, credential).
//!
//! Before this, ownership was the credential alone, so two people behind one
//! shared API key (or, with auth off, behind no key at all) could resume and
//! delete each other's sessions and read each other's notifications. Every row
//! drives the real router on all three session routes (POST, GET, DELETE): a
//! subject that resolves on POST but not on GET would lock its owner out of
//! its own stream.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::router::AppState;
use crate::gateway::router::create_router;
use crate::gateway::router::tests::{test_router_app_state, test_router_app_state_with_auth};

const KEY_ONE: &str = "shared-key-one-0123456789";
const KEY_TWO: &str = "shared-key-two-0123456789";

fn api_key(secret: &str, name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// Auth on with two API keys, each shared by whoever holds it.
fn two_keys() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![api_key(KEY_ONE, "one"), api_key(KEY_TWO, "two")],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    }
}

/// Who is calling: an OAuth-agent subject (the proof the router reads from the
/// request extensions) and the bearer credential it presents.
#[derive(Clone, Copy)]
struct Caller {
    agent: Option<&'static str>,
    bearer: Option<&'static str>,
}

const fn caller(agent: Option<&'static str>, bearer: Option<&'static str>) -> Caller {
    Caller { agent, bearer }
}

fn request(who: Caller, method: &str, session: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri("/mcp");
    builder = match method {
        "POST" => builder.header("content-type", "application/json"),
        "GET" => builder.header("accept", "text/event-stream"),
        _ => builder,
    };
    if let Some(id) = session {
        builder = builder.header("mcp-session-id", id);
    }
    if let Some(bearer) = who.bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let body = if method == "POST" {
        Body::from(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string())
    } else {
        Body::empty()
    };
    let mut request = builder.body(body).unwrap();
    if let Some(client_id) = who.agent {
        request.extensions_mut().insert(OAuthAgentIdentity {
            quota_principal: None,
            client_id: client_id.to_string(),
            agent_name: "one display name for every agent".to_string(),
            scopes: vec![],
            raw_scopes: vec![],
        });
    }
    request
}

/// The status and the session id the route answered with.
async fn send(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, Option<String>) {
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    (response.status(), session)
}

/// A POST that minted a fresh session; its id.
async fn mint(state: &Arc<AppState>, who: Caller) -> String {
    let (status, id) = send(state, request(who, "POST", None)).await;
    assert_eq!(status, StatusCode::OK, "the minting POST was refused");
    id.expect("a legacy POST is given a session")
}

/// Whether `who` presenting `id` on `method` got that same session back.
async fn resumes(state: &Arc<AppState>, who: Caller, method: &str, id: &str) -> bool {
    let (status, got) = send(state, request(who, method, Some(id))).await;
    assert_eq!(status, StatusCode::OK, "{method} was refused outright");
    got.as_deref() == Some(id)
}

const A_ON_ONE: Caller = caller(Some("agent-a"), Some(KEY_ONE));
const B_ON_ONE: Caller = caller(Some("agent-b"), Some(KEY_ONE));
const A_ON_TWO: Caller = caller(Some("agent-a"), Some(KEY_TWO));

#[tokio::test]
async fn cross_subject_session_refused() {
    let (state, _store) = test_router_app_state_with_auth(&two_keys()).await;
    let a = mint(&state, A_ON_ONE).await;
    for method in ["POST", "GET"] {
        assert!(
            !resumes(&state, B_ON_ONE, method, &a).await,
            "subject B resumed subject A's session on {method} through their shared key"
        );
    }
    assert!(
        resumes(&state, A_ON_ONE, "POST", &a).await,
        "B's attempts must not have displaced A's session"
    );
}

#[tokio::test]
async fn cross_subject_delete_refused() {
    let (state, _store) = test_router_app_state_with_auth(&two_keys()).await;
    let a = mint(&state, A_ON_ONE).await;
    let (status, _) = send(&state, request(B_ON_ONE, "DELETE", Some(&a))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "subject B deleted subject A's session through their shared key"
    );
    assert!(state.multiplexer.has_session(&a));
}

#[tokio::test]
async fn one_subject_resumes_and_deletes_its_own_session_on_every_route() {
    let (state, _store) = test_router_app_state_with_auth(&two_keys()).await;
    let a = mint(&state, A_ON_ONE).await;
    assert!(resumes(&state, A_ON_ONE, "POST", &a).await, "POST resume");
    assert!(resumes(&state, A_ON_ONE, "GET", &a).await, "GET resume");
    let (status, _) = send(&state, request(A_ON_ONE, "DELETE", Some(&a))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the owner's DELETE");
    assert!(!state.multiplexer.has_session(&a));
}

#[tokio::test]
async fn same_subject_other_credential_new_session() {
    // A resumed session's held credential is overwritten on resume, so one
    // subject's two credentials (different scopes) must never share one.
    let (state, _store) = test_router_app_state_with_auth(&two_keys()).await;
    let a = mint(&state, A_ON_ONE).await;
    for method in ["POST", "GET"] {
        assert!(
            !resumes(&state, A_ON_TWO, method, &a).await,
            "the same subject under another credential resumed the session on {method}"
        );
    }
}

#[tokio::test]
async fn a_subject_without_a_credential_owns_its_session() {
    // Auth off: every caller used to be "anonymous", so a proven subject's
    // session was open to any other caller holding its id.
    let (state, _store) = test_router_app_state().await;
    let a = mint(&state, caller(Some("agent-a"), None)).await;
    for other in [caller(Some("agent-b"), None), caller(None, None)] {
        for method in ["POST", "GET"] {
            assert!(
                !resumes(&state, other, method, &a).await,
                "another caller resumed a subject's session on {method}"
            );
        }
    }
    assert!(
        resumes(&state, caller(Some("agent-a"), None), "GET", &a).await,
        "the subject lost its own session"
    );
}

/// A signed agent JWT for `client_id`, registered in `registry`.
fn real_agent_token(registry: &crate::gateway::oauth::AgentRegistry, client_id: &str) -> String {
    let secret = format!("{client_id}-session-owner-secret-0123456789");
    registry.register(crate::gateway::oauth::AgentDefinition {
        client_id: client_id.to_string(),
        name: "one display name for every agent".to_string(),
        hs256_secret: Some(secret.clone()),
        rs256_public_key: None,
        scopes: vec![],
        issuer: None,
        audience: Some("session-owner".to_string()),
    });
    let now = chrono::Utc::now().timestamp();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({ "sub": client_id, "exp": now + 3600, "iat": now, "aud": "session-owner" }),
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("sign agent token")
}

#[tokio::test]
async fn a_real_agent_token_owns_its_session_on_every_route() {
    // Through the production auth layers, not a hand-inserted extension: a
    // subject the layers resolved on POST only would lock the agent out of GET.
    let (mut state, _store) = test_router_app_state().await;
    let registry = Arc::new(crate::gateway::oauth::AgentRegistry::new());
    let (own, other) = (
        real_agent_token(&registry, "agent-real-a"),
        real_agent_token(&registry, "agent-real-b"),
    );
    Arc::get_mut(&mut state)
        .expect("no other state handle")
        .agent_auth = crate::gateway::oauth::AgentAuthState::new(true, registry);
    let bearer = |token: &str, method: &str, session: Option<&str>| {
        let mut request = request(caller(None, None), method, session);
        request
            .headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    };
    let (status, id) = send(&state, bearer(&own, "POST", None)).await;
    assert_eq!(status, StatusCode::OK, "the minting POST was refused");
    let a = id.expect("a legacy POST is given a session");
    let (status, got) = send(&state, bearer(&other, "GET", Some(&a))).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        got.as_deref(),
        Some(a.as_str()),
        "another agent resumed on GET"
    );
    let (status, got) = send(&state, bearer(&own, "GET", Some(&a))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        got.as_deref(),
        Some(a.as_str()),
        "the agent lost its own stream"
    );
    let (status, _) = send(&state, bearer(&own, "DELETE", Some(&a))).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the owner's DELETE");
}

#[tokio::test]
async fn same_subject_other_presented_token_new_session() {
    // A delegated OIDC bearer's validated principal is its stable actor, not
    // the token, so the principal cannot tell one subject's two tokens apart.
    // Here nothing validates the bearer at all (auth off): only the presented
    // token differs, and it alone must split the session.
    let (state, _store) = test_router_app_state().await;
    let a = mint(&state, caller(Some("agent-a"), Some("token-one"))).await;
    for method in ["POST", "GET"] {
        assert!(
            !resumes(
                &state,
                caller(Some("agent-a"), Some("token-two")),
                method,
                &a
            )
            .await,
            "the same subject under another presented token resumed the session on {method}"
        );
    }
    let other = caller(Some("agent-a"), Some("token-two"));
    let (status, _) = send(&state, request(other, "DELETE", Some(&a))).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another token deleted the session"
    );
    assert!(
        resumes(
            &state,
            caller(Some("agent-a"), Some("token-one")),
            "GET",
            &a
        )
        .await,
        "the subject lost its own session"
    );
}

/// MIK-7215.CONTROL.5, gap G2: the owner's DELETE ends the session, so the
/// per-session stores keyed by its id are reclaimed, and another session's are
/// not.
#[tokio::test]
async fn an_owned_delete_reclaims_the_per_session_stores() {
    let (state, _store) = test_router_app_state().await;
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("the test owns the state"));
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    crate::gateway::session_lifecycle::wire_meta_session_cleanup(&lifecycle, &state.meta_mcp);
    state.session_lifecycle = Some(lifecycle);
    let state = Arc::new(state);

    let gone = mint(&state, caller(Some("agent-a"), None)).await;
    let kept = mint(&state, caller(Some("agent-b"), None)).await;
    for id in [&gone, &kept] {
        state.meta_mcp.session_profiles().set_profile(id, "strict");
        state
            .meta_mcp
            .cost_tracker()
            .record(id, None, "backend", "tool", 10, 1.0);
    }

    let (status, _) = send(
        &state,
        request(caller(Some("agent-a"), None), "DELETE", Some(&gone)),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        state
            .meta_mcp
            .session_profiles()
            .get_profile_name(&gone, "default"),
        "default"
    );
    assert!(
        state
            .meta_mcp
            .cost_tracker()
            .session_snapshot(&gone)
            .is_none()
    );
    assert_eq!(
        state
            .meta_mcp
            .session_profiles()
            .get_profile_name(&kept, "default"),
        "strict"
    );
    assert!(
        state
            .meta_mcp
            .cost_tracker()
            .session_snapshot(&kept)
            .is_some()
    );
}

/// The idle deadline is not a session end: a legacy session that is only quiet
/// keeps its profile and cost bucket through the 5-minute reclaim sweep.
#[tokio::test]
async fn a_live_session_keeps_its_stores_through_the_idle_reclaim() {
    let (state, _store) = test_router_app_state().await;
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("the test owns the state"));
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    crate::gateway::session_lifecycle::wire_meta_session_cleanup(&lifecycle, &state.meta_mcp);
    state.session_lifecycle = Some(Arc::clone(&lifecycle));
    let state = Arc::new(state);

    let live = mint(&state, caller(Some("agent-a"), None)).await;
    state
        .meta_mcp
        .session_profiles()
        .set_profile(&live, "strict");
    state
        .meta_mcp
        .cost_tracker()
        .record(&live, None, "backend", "tool", 10, 1.0);
    // With no caller key the firewall tracks the session id itself.
    lifecycle.track(live.clone(), 0);

    assert_eq!(lifecycle.reap(1), 1, "the deadline passed and was swept");

    assert!(
        state.multiplexer.has_session(&live),
        "the session is still open"
    );
    assert_eq!(
        state
            .meta_mcp
            .session_profiles()
            .get_profile_name(&live, "default"),
        "strict",
        "an idle sweep must not reset a live session's profile"
    );
    assert!(
        state
            .meta_mcp
            .cost_tracker()
            .session_snapshot(&live)
            .is_some()
    );
}

/// A legacy session that only POSTs holds no stream, so it is always "without
/// receivers"; the reaper must go by its last activity, not its age, or a busy
/// session is replaced mid-use and starts again on the default profile.
///
/// On a paused clock (MIK-8280): session age and the reaper's tick both read
/// tokio time (#3739), so each round is exactly 40 ms of it, however loaded
/// the runner. On the real clock a stalled round outlived the 150 ms TTL.
#[tokio::test(start_paused = true)]
async fn a_session_older_than_the_ttl_that_stays_active_keeps_its_profile() {
    let streaming = crate::config::StreamingConfig {
        session_ttl: std::time::Duration::from_millis(150),
        session_reaper_interval: std::time::Duration::from_millis(20),
        ..crate::config::StreamingConfig::default()
    };
    let (state, _store) =
        crate::gateway::router::tests::test_router_app_state_with_streaming(streaming).await;
    let lifecycle = Arc::new(crate::gateway::session_lifecycle::SessionLifecycle::new());
    crate::gateway::session_lifecycle::wire_meta_session_cleanup(&lifecycle, &state.meta_mcp);
    state.multiplexer.spawn_reaper_on(Arc::clone(&lifecycle));

    let live = mint(&state, caller(Some("agent-a"), None)).await;
    state
        .meta_mcp
        .session_profiles()
        .set_profile(&live, "strict");

    // Three times the TTL, never quiet for longer than a quarter of it.
    for round in 0..12 {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(
            resumes(&state, caller(Some("agent-a"), None), "POST", &live).await,
            "round {round}: the active session was replaced"
        );
    }
    assert_eq!(
        state
            .meta_mcp
            .session_profiles()
            .get_profile_name(&live, "default"),
        "strict"
    );
}
