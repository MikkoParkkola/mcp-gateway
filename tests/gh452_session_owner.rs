// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH452.SESSION.1-.7: legacy DELETE must enforce the owner used by GET/POST.
//! IDs and caller identities are established through the production router.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, BodyDataStream, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::response::Response;
use futures::StreamExt;
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::{ApiKeyConfig, AuthConfig, Config};
use mcp_gateway::gateway::auth::{DashboardBootstrap, ResolvedAuthConfig};
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::{NotificationMultiplexer, TaggedNotification};
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, create_router, open_runtime,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE_KEY: &str = "gh452-alice-test-credential";
const BOB_KEY: &str = "gh452-bob-test-credential";

/// The gateway under test, plus the directory its task store leases.
///
/// The `TempDir` comes back because the store holds its directory for as long
/// as the service lives, and these cases keep streams open across several
/// requests: a directory dropped here would be deleted under a gateway still
/// answering. Every call gets its own, so no two cases share a lease.
async fn state(
    auth_enabled: bool,
    public_mcp: bool,
    names: [&str; 2],
) -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = Config {
        auth: AuthConfig {
            enabled: auth_enabled,
            api_keys: [ALICE_KEY, BOB_KEY]
                .into_iter()
                .zip(names)
                .map(|(key, name)| ApiKeyConfig {
                    key: key.to_owned(),
                    name: name.to_owned(),
                    rate_limit: 0,
                    backends: vec!["*".to_owned()],
                    allowed_tools: None,
                    denied_tools: None,
                    admin: false,
                })
                .collect(),
            public_paths: if public_mcp {
                vec!["/mcp".to_owned()]
            } else {
                vec!["/health".to_owned()]
            },
            ..AuthConfig::default()
        },
        ..Config::default()
    };
    config.streaming.enabled = true;
    config.streaming.auto_subscribe.clear();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    // One registry for both the state the router reads and the executor that
    // publishes through it: two would strand a task's notifications.
    let subscriptions = Arc::new(SubscriptionRegistry::new(64));
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");

    let state = Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        tasks,
        task_executor,
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
        backends,
        meta_mcp_enabled: true,
        proxy_manager: Arc::new(ProxyManager::new(Arc::clone(&multiplexer))),
        multiplexer,
        streaming_config: config.streaming.clone(),
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(100)),
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("test key pair")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config)),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
        subscriptions,
    });
    (state, store_dir)
}

fn request(method: Method, key: Option<&str>) -> axum::http::request::Builder {
    let mut request = Request::builder()
        .method(method)
        .uri("/mcp")
        .header("mcp-protocol-version", "2025-11-25");
    if let Some(key) = key {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    request
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> Response {
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router answers")
}

async fn delete(state: &Arc<AppState>, key: Option<&str>, id: Option<&str>) -> Response {
    let mut request = request(Method::DELETE, key);
    if let Some(id) = id {
        request = request.header("mcp-session-id", id);
    }
    send(state, request.body(Body::empty()).expect("DELETE request")).await
}

async fn response_parts(response: Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, 16_384).await.expect("bounded body").to_vec(),
    )
}

struct Session {
    id: String,
    stream: BodyDataStream,
}

async fn next_event(stream: &mut BodyDataStream) -> String {
    let bytes = tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .expect("SSE event arrives within deadline")
        .expect("original stream remains open")
        .expect("SSE body readable");
    String::from_utf8(bytes.to_vec()).expect("SSE UTF-8")
}

async fn open_session(state: &Arc<AppState>, key: Option<&str>, id: Option<&str>) -> Session {
    let mut request = request(Method::GET, key).header("accept", "text/event-stream");
    if let Some(id) = id {
        request = request.header("mcp-session-id", id);
    }
    let response = send(state, request.body(Body::empty()).expect("GET request")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let id = response.headers()["mcp-session-id"]
        .to_str()
        .expect("session header")
        .to_owned();
    let mut stream = response.into_body().into_data_stream();
    let connected = next_event(&mut stream).await;
    assert!(connected.contains("event: connected"), "{connected}");
    assert!(connected.contains(&id), "{connected}");
    Session { id, stream }
}

fn notification(marker: &str) -> TaggedNotification {
    TaggedNotification {
        source: "gh452-test".to_owned(),
        event_type: "message".to_owned(),
        data: json!({"jsonrpc": "2.0", "method": "notifications/test", "params": {"marker": marker}}),
        event_id: None,
    }
}

async fn prove_original_stream(state: &Arc<AppState>, session: &mut Session, marker: &str) {
    assert!(state.multiplexer.has_session(&session.id));
    assert!(
        state
            .multiplexer
            .send_to_session(&session.id, notification(marker)),
        "the original session must accept a notification"
    );
    let event = next_event(&mut session.stream).await;
    assert!(event.contains("event: message"), "{event}");
    assert!(event.contains(marker), "{event}");
}

async fn post(state: &Arc<AppState>, key: &str, id: Option<&str>, body: Value) -> Response {
    let mut request = request(Method::POST, Some(key))
        .header("content-type", "application/json")
        .header("accept", "application/json");
    if let Some(id) = id {
        request = request.header("mcp-session-id", id);
    }
    send(
        state,
        request
            .body(Body::from(serde_json::to_vec(&body).expect("JSON body")))
            .expect("POST request"),
    )
    .await
}

async fn prove_ping(state: &Arc<AppState>, key: &str, session: &Session) {
    let response = post(
        state,
        key,
        Some(&session.id),
        json!({"jsonrpc": "2.0", "id": 42, "method": "ping"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["mcp-session-id"], session.id);
    let bytes = to_bytes(response.into_body(), 16_384)
        .await
        .expect("ping body");
    let body: Value = serde_json::from_slice(&bytes).expect("JSON ping result");
    assert_eq!(body["id"], 42);
    assert!(body.get("result").is_some(), "{body}");
    assert!(body.get("error").is_none(), "{body}");
}

/// GH452.SESSION.1: refusal must preserve the actual live stream, not recreate it.
#[tokio::test]
async fn gh452_session_1_foreign_delete_preserves_original_stream_and_calls() {
    let (state, _store_dir) = state(true, false, ["alice", "bob"]).await;
    let mut alice = open_session(&state, Some(ALICE_KEY), None).await;
    let mut bob = open_session(&state, Some(BOB_KEY), None).await;
    assert_ne!(alice.id, bob.id);

    let response = delete(&state, Some(BOB_KEY), Some(&alice.id)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(state.multiplexer.session_count(), 2);
    prove_original_stream(&state, &mut alice, "alice-survived-foreign-delete").await;
    prove_original_stream(&state, &mut bob, "bob-was-unaffected").await;
    prove_ping(&state, ALICE_KEY, &alice).await;
    prove_ping(&state, BOB_KEY, &bob).await;
    assert_eq!(state.multiplexer.session_count(), 2);
}

/// GH452.SESSION.2: POST creation, GET resumption and DELETE use the same owner.
#[tokio::test]
async fn gh452_session_2_owner_deletes_post_created_session_once() {
    let (state, _store_dir) = state(true, false, ["alice", "bob"]).await;
    let initialized = post(
        &state,
        ALICE_KEY,
        None,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "gh452-client", "version": "1.0"}
            }
        }),
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::OK);
    let id = initialized.headers()["mcp-session-id"]
        .to_str()
        .expect("POST session id")
        .to_owned();
    let mut alice = open_session(&state, Some(ALICE_KEY), Some(&id)).await;
    assert_eq!(alice.id, id);
    let mut bob = open_session(&state, Some(BOB_KEY), None).await;
    prove_original_stream(&state, &mut alice, "owner-stream-before-delete").await;

    let response = delete(&state, Some(ALICE_KEY), Some(&id)).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!state.multiplexer.has_session(&id));
    assert_eq!(state.multiplexer.session_count(), 1);
    assert!(!state.multiplexer.send_to_session(&id, notification("gone")));
    assert_eq!(
        delete(&state, Some(ALICE_KEY), Some(&id)).await.status(),
        StatusCode::NOT_FOUND
    );
    prove_original_stream(&state, &mut bob, "other-owner-still-live").await;
    prove_ping(&state, BOB_KEY, &bob).await;
}

/// GH452.SESSION.3: exact response comparison catches an existence oracle.
#[tokio::test]
async fn gh452_session_3_foreign_and_unknown_are_indistinguishable() {
    let (state, _store_dir) = state(true, false, ["alice", "bob"]).await;
    let mut alice = open_session(&state, Some(ALICE_KEY), None).await;
    let unknown =
        response_parts(delete(&state, Some(BOB_KEY), Some("gh452-never-created")).await).await;
    let foreign = response_parts(delete(&state, Some(BOB_KEY), Some(&alice.id)).await).await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    assert!(unknown.2.is_empty());
    assert_eq!(foreign, unknown);
    assert_eq!(state.multiplexer.session_count(), 1);
    prove_original_stream(&state, &mut alice, "not-found-does-not-delete").await;
}

/// GH452.SESSION.4: malformed/missing IDs are tested after valid authentication.
#[tokio::test]
async fn gh452_session_4_session_header_boundaries_after_authentication() {
    let (state, _store_dir) = state(true, false, ["alice", "bob"]).await;
    let mut alice = open_session(&state, Some(ALICE_KEY), None).await;
    assert_eq!(
        delete(&state, Some(ALICE_KEY), None).await.status(),
        StatusCode::BAD_REQUEST
    );
    let invalid = request(Method::DELETE, Some(ALICE_KEY))
        .header(
            "mcp-session-id",
            HeaderValue::from_bytes(&[0xff]).expect("non-text header bytes"),
        )
        .body(Body::empty())
        .expect("non-text session header request");
    assert_eq!(
        send(&state, invalid).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        delete(&state, Some(ALICE_KEY), Some("")).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(state.multiplexer.session_count(), 1);
    prove_original_stream(&state, &mut alice, "bad-header-does-not-delete").await;
}

/// GH452.SESSION.4: the compatibility promise applies only with auth disabled.
#[tokio::test]
async fn gh452_session_4_auth_disabled_anonymous_owner_can_delete() {
    let (state, _store_dir) = state(false, false, ["alice", "bob"]).await;
    let session = open_session(&state, None, None).await;
    assert_eq!(
        delete(&state, None, Some(&session.id)).await.status(),
        StatusCode::NO_CONTENT
    );
    assert!(!state.multiplexer.has_session(&session.id));
    assert_eq!(state.multiplexer.session_count(), 0);
}

/// GH452.SESSION.4: ordinary authenticated routes still reject missing credentials.
#[tokio::test]
async fn gh452_session_4_authenticated_route_refuses_missing_credentials() {
    let (state, _store_dir) = state(true, false, ["alice", "bob"]).await;
    let mut alice = open_session(&state, Some(ALICE_KEY), None).await;
    let response = delete(&state, None, Some(&alice.id)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["www-authenticate"], "Bearer");
    prove_original_stream(&state, &mut alice, "missing-credential-refused").await;
}

/// GH452.SESSION.5: real credentials with colliding display names remain distinct.
#[tokio::test]
async fn gh452_session_5_same_display_name_is_not_the_same_credential() {
    for name in ["shared", "anonymous"] {
        let (state, _store_dir) = state(true, false, [name, name]).await;
        let mut alice = open_session(&state, Some(ALICE_KEY), None).await;
        let mut bob = open_session(&state, Some(BOB_KEY), None).await;
        assert_ne!(alice.id, bob.id);
        assert_eq!(
            delete(&state, Some(BOB_KEY), Some(&alice.id))
                .await
                .status(),
            StatusCode::NOT_FOUND,
            "different secrets must not share ownership under display name {name}"
        );
        prove_original_stream(&state, &mut alice, "same-name-foreign-refused").await;
        assert_eq!(state.multiplexer.session_count(), 2);
        assert_eq!(
            delete(&state, Some(ALICE_KEY), Some(&alice.id))
                .await
                .status(),
            StatusCode::NO_CONTENT,
            "valid original owner must still be recognized"
        );
        prove_original_stream(&state, &mut bob, "same-name-owner-delete-leaves-bob").await;
        prove_ping(&state, BOB_KEY, &bob).await;
        assert_eq!(state.multiplexer.session_count(), 1);
    }
}

/// GH452.SESSION.6: competing requests supplement the single-write-guard review.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gh452_session_6_only_one_competing_owner_delete_succeeds() {
    let (state, _store_dir) = state(true, false, ["alice", "bob"]).await;
    let alice = open_session(&state, Some(ALICE_KEY), None).await;
    let mut bob = open_session(&state, Some(BOB_KEY), None).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(4));
    let mut requests = tokio::task::JoinSet::new();
    for key in [ALICE_KEY, ALICE_KEY, BOB_KEY] {
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        let id = alice.id.clone();
        requests.spawn(async move {
            barrier.wait().await;
            (key, delete(&state, Some(key), Some(&id)).await.status())
        });
    }
    barrier.wait().await;
    let mut owner_successes = 0;
    while let Some(result) = requests.join_next().await {
        let (key, status) = result.expect("DELETE task completed");
        if key == BOB_KEY {
            assert_eq!(status, StatusCode::NOT_FOUND);
        } else if status == StatusCode::NO_CONTENT {
            owner_successes += 1;
        } else {
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
    }
    assert_eq!(owner_successes, 1);
    assert!(!state.multiplexer.has_session(&alice.id));
    assert_eq!(state.multiplexer.session_count(), 1);
    prove_original_stream(&state, &mut bob, "competing-deletes-leave-bob").await;
}

/// GH452.SESSION.7: public-path middleware fallback is not a DELETE owner identity.
#[tokio::test]
async fn gh452_session_7_public_anonymous_delete_requires_a_validated_principal() {
    let (state, _store_dir) = state(true, true, ["alice", "bob"]).await;
    let mut public = open_session(&state, None, None).await;
    let expected = response_parts(delete(&state, None, Some("gh452-unknown-public")).await).await;
    assert_eq!(expected.0, StatusCode::UNAUTHORIZED);
    assert_eq!(expected.1["www-authenticate"], "Bearer");
    for (key, id) in [
        (None, Some(public.id.as_str())),
        (None, None),
        (Some("gh452-invalid-credential"), Some(public.id.as_str())),
    ] {
        let actual = response_parts(delete(&state, key, id).await).await;
        assert_eq!(actual, expected, "no credential means no session lookup");
    }
    assert_eq!(state.multiplexer.session_count(), 1);
    prove_original_stream(&state, &mut public, "public-session-survives").await;
}

/// GH452.SESSION.7: public paths validate supplied keys before public fallback.
#[tokio::test]
async fn gh452_session_7_public_valid_credential_owner_can_delete() {
    let (state, _store_dir) = state(true, true, ["alice", "bob"]).await;
    let mut public = open_session(&state, None, None).await;
    let alice = open_session(&state, Some(ALICE_KEY), None).await;
    assert_eq!(
        delete(&state, Some(ALICE_KEY), Some(&alice.id))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(!state.multiplexer.has_session(&alice.id));
    assert_eq!(state.multiplexer.session_count(), 1);
    prove_original_stream(&state, &mut public, "authenticated-delete-leaves-public").await;
}

/// GH452.SESSION.7: a valid credential does not own an anonymous public session.
#[tokio::test]
async fn gh452_session_7_public_session_rejects_authenticated_nonowner() {
    let (state, _store_dir) = state(true, true, ["alice", "bob"]).await;
    let mut public = open_session(&state, None, None).await;
    let mut alice = open_session(&state, Some(ALICE_KEY), None).await;
    assert_ne!(public.id, alice.id);
    assert_eq!(
        delete(&state, Some(ALICE_KEY), Some(&public.id))
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "a valid key does not authorize deletion of another owner's public session"
    );
    assert_eq!(state.multiplexer.session_count(), 2);
    prove_original_stream(
        &state,
        &mut public,
        "public-survives-authenticated-nonowner",
    )
    .await;
    prove_original_stream(
        &state,
        &mut alice,
        "authenticated-nonowner-keeps-own-stream",
    )
    .await;
    prove_ping(&state, ALICE_KEY, &alice).await;
    assert_eq!(state.multiplexer.session_count(), 2);
}
