// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2300: a passthrough caller picks its own slot key. The binding hashes the
//! unverified `x-mcp-passthrough-authorization` header, so each new header
//! value used to mint a new `PerUser` slot with its own transport. A backend
//! now admits at most `CAP` identity slots (MIK-7547.SLOTS.1) and one
//! principal at most `PER_PRINCIPAL`; every anonymous caller is one principal.
//! Past a limit the caller is refused, never moved onto the shared slot.
//!
//! Each cell asserts an EXACT slot count: fewer would mean the requests were
//! refused before reaching the pool, which proves nothing about the limits.

use axum::http::StatusCode;
use serde_json::json;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::router::create_router;
use crate::gateway::router::tests::direct_route_state_with_identity;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::transport::Transport;

/// The per-backend identity-slot cap (MIK-7547.SLOTS.1).
const CAP: usize = 64;
/// Identity slots one principal may hold on one backend.
const PER_PRINCIPAL: usize = 8;
/// More distinct header values than one principal may hold.
const HEADERS: usize = PER_PRINCIPAL + 2;

/// A stateful (`session_mode = per_user`) passthrough backend. Not `required`,
/// so no transport check refuses before the slot is derived. The default HTTP
/// transport has no URL, so every start fails at once, after the slot exists.
fn passthrough_backend() -> Arc<Backend> {
    Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::Passthrough,
                audience: "ledger".to_string(),
                required: false,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

async fn router_with(backend: &Arc<Backend>) -> (axum::Router, tempfile::TempDir) {
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(
        state_mut.backends.register(Arc::clone(backend)),
        "fixture registration"
    );
    (create_router(state), store)
}

fn header_value(i: usize) -> String {
    format!("Bearer caller-{i}")
}

/// POST one JSON-RPC message to `/mcp/ledger` carrying passthrough header `i`,
/// as `subject` (a verified identity) or anonymously (auth disabled), and
/// return the status and body.
async fn send(
    router: &axum::Router,
    i: usize,
    subject: Option<&str>,
    notification: bool,
) -> (StatusCode, String) {
    let body = if notification {
        json!({ "jsonrpc": "2.0", "method": "notifications/roots/list_changed" })
    } else {
        json!({ "jsonrpc": "2.0", "id": i, "method": "resources/list" })
    };
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .header("x-mcp-passthrough-authorization", header_value(i))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    if let Some(subject) = subject {
        request.extensions_mut().insert(VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://idp.example.invalid".to_string(),
        });
    }
    let response = router.clone().oneshot(request).await.unwrap();
    // Callers that only count slots ignore the status: a 5xx is expected,
    // because the fixture transport cannot start.
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// GIVEN auth disabled, so every caller is the one anonymous principal
/// WHEN more distinct passthrough headers than a principal may hold each send
/// a request
/// THEN the anonymous callers together hold exactly `PER_PRINCIPAL` slots.
#[tokio::test]
async fn anonymous_passthrough_callers_share_one_principal_budget() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    for i in 0..HEADERS {
        send(&router, i, None, false).await;
    }
    assert_eq!(backend.per_user_slots_for_test(), PER_PRINCIPAL);
}

/// GIVEN one verified caller that varies its passthrough header per request
/// WHEN it sends more header values than a principal may hold, and then a
/// second verified caller sends one
/// THEN the first holds exactly `PER_PRINCIPAL` slots and the second is still
/// admitted.
#[tokio::test]
async fn one_principal_at_its_budget_does_not_lock_out_another() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    for i in 0..HEADERS {
        send(&router, i, Some("alpha"), false).await;
    }
    assert_eq!(backend.per_user_slots_for_test(), PER_PRINCIPAL);
    send(&router, HEADERS, Some("beta"), false).await;
    assert_eq!(backend.per_user_slots_for_test(), PER_PRINCIPAL + 1);
}

/// GIVEN enough verified principals that their budgets exceed the backend cap
/// WHEN each sends `PER_PRINCIPAL` distinct passthrough headers
/// THEN the backend holds exactly `CAP` identity slots.
#[tokio::test]
async fn many_principals_never_exceed_the_backend_cap() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    let principals = CAP / PER_PRINCIPAL + 1;
    for p in 0..principals {
        let subject = format!("p{p}");
        for h in 0..PER_PRINCIPAL {
            send(&router, p * PER_PRINCIPAL + h, Some(&subject), false).await;
        }
    }
    assert_eq!(backend.per_user_slots_for_test(), CAP);
}

/// GIVEN the notification path, which resolves the same binding outside the
/// request path
/// WHEN anonymous callers send more distinct passthrough headers than a
/// principal may hold, each as a notification
/// THEN no slot is created past the anonymous budget.
#[tokio::test]
async fn passthrough_notifications_respect_the_principal_budget() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    for i in 0..HEADERS {
        send(&router, i, None, true).await;
    }
    assert_eq!(backend.per_user_slots_for_test(), PER_PRINCIPAL);
}

/// GIVEN the anonymous principal at its budget
/// WHEN an admitted caller comes back with the same header
/// THEN it is served on its existing slot and nothing else changes: the
/// budget refuses new bindings, it never evicts an admitted one.
#[tokio::test]
async fn an_admitted_caller_keeps_its_slot_at_the_budget() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    for i in 0..HEADERS {
        send(&router, i, None, false).await;
    }
    let before = backend.per_user_slot_bindings_for_test();
    send(&router, 0, None, false).await;
    assert_eq!(backend.per_user_slot_bindings_for_test(), before);
    assert_eq!(before.len(), PER_PRINCIPAL);
}

/// A transport that records the method of every request and notification
/// reaching it. On the shared slot it is the oracle for "an over-budget caller
/// never lands there": the slot counts above cannot tell a refusal from a
/// fallback to `Shared`, because a fallback mints no `PerUser` slot either.
struct RecordingTransport(Arc<Mutex<Vec<String>>>);

#[async_trait::async_trait]
impl Transport for RecordingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.0.lock().unwrap().push(method.to_string());
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            json!({ "resources": [] }),
        ))
    }
    async fn notify(&self, method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        self.0.lock().unwrap().push(method.to_string());
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// MIK-7547.TEST.1. GIVEN the anonymous principal at its budget, and a
/// recording transport on the shared slot
/// WHEN a caller with a new passthrough header sends a request, then a
/// notification
/// THEN the request is answered with the slot refusal, the notification with
/// 429, and neither reaches the shared slot. Red if the cap path hands the
/// caller `PoolKey::Shared` (#727).
#[tokio::test]
async fn an_over_budget_caller_is_refused_and_never_reaches_the_shared_slot() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    for i in 0..PER_PRINCIPAL {
        send(&router, i, None, false).await;
    }
    assert_eq!(backend.per_user_slots_for_test(), PER_PRINCIPAL);
    let shared = Arc::new(Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(RecordingTransport(Arc::clone(&shared))));

    let (status, body) = send(&router, PER_PRINCIPAL, None, false).await;
    assert!(
        body.contains("has no free caller slot (principal limit reached)"),
        "the over-budget request must get the slot refusal, got {status}: {body}"
    );
    let (status, _) = send(&router, PER_PRINCIPAL + 1, None, true).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "over-budget notification"
    );

    let reached = shared.lock().unwrap().clone();
    assert!(
        !reached
            .iter()
            .any(|m| m == "resources/list" || m == "notifications/roots/list_changed"),
        "an over-budget caller reached the shared slot: {reached:?}"
    );
    assert_eq!(backend.per_user_slots_for_test(), PER_PRINCIPAL);
}

fn api_key(key: &str) -> crate::config::ApiKeyConfig {
    crate::config::ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: format!("{key}-client"),
        rate_limit: 0,
        backends: vec!["ledger".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// GIVEN auth on with two API keys, and no verified identity
/// WHEN each key's caller sends more distinct passthrough headers than a
/// principal may hold
/// THEN each key is charged its own budget, not the anonymous one.
#[tokio::test]
async fn api_key_callers_each_get_their_own_budget() {
    let backend = passthrough_backend();
    let auth = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![api_key("key-one"), api_key("key-two")],
        ..crate::config::AuthConfig::default()
    };
    let (mut state, _store) =
        crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await;
    assert!(
        Arc::get_mut(&mut state)
            .expect("state is unique")
            .backends
            .register(Arc::clone(&backend)),
        "fixture registration"
    );
    let router = create_router(state);
    for key in ["key-one", "key-two"] {
        for i in 0..HEADERS {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/mcp/ledger")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {key}"))
                .header("x-mcp-passthrough-authorization", header_value(i))
                .body(axum::body::Body::from(
                    json!({ "jsonrpc": "2.0", "id": i, "method": "resources/list" }).to_string(),
                ))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_ne!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{key} was not accepted"
            );
        }
    }
    assert_eq!(backend.per_user_slots_for_test(), 2 * PER_PRINCIPAL);
}

/// GIVEN two mutual-TLS callers, each proven by its client certificate and
/// with no API key or verified identity
/// WHEN each sends more distinct passthrough headers than a principal may hold
/// THEN each certificate is charged its own budget, not the anonymous one.
#[tokio::test]
async fn certificate_callers_each_get_their_own_budget() {
    let backend = passthrough_backend();
    let (router, _store) = router_with(&backend).await;
    for machine in ["machine-1", "machine-2"] {
        for i in 0..HEADERS {
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/mcp/ledger")
                .header("content-type", "application/json")
                .header("x-mcp-passthrough-authorization", header_value(i))
                .body(axum::body::Body::from(
                    json!({ "jsonrpc": "2.0", "id": i, "method": "resources/list" }).to_string(),
                ))
                .unwrap();
            request
                .extensions_mut()
                .insert(crate::mtls::identity::CertIdentity {
                    display_name: machine.to_string(),
                    ..Default::default()
                });
            let _ = router.clone().oneshot(request).await.unwrap();
        }
    }
    assert_eq!(backend.per_user_slots_for_test(), 2 * PER_PRINCIPAL);
}
