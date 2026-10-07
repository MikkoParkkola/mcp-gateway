// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2240: a notification on the direct route is forwarded only when the same
//! caller's request on that backend would be. A refused credential, a refused
//! passthrough, an unbound account backend and a shared personal login on a
//! multi-user gateway each answer 403 with the `{}` an accepted notification
//! gets, and reach no upstream slot. A backend with no personal binding still
//! forwards on the shared session (IDP.5).

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::direct_route_state_with_identity;
use crate::backend::{Backend, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::test_helpers::MetaMcp;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const NOTE: &str = "notifications/roots/list_changed";

/// Mints `Bearer minted-for-<subject>` bound to `<subject>@<audience>`.
struct PerIdentityMint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for PerIdentityMint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        let subject_key = identity.subject.clone();
        Ok(crate::identity_propagation::PropagatedCredential {
            headers: vec![(
                "Authorization".to_string(),
                format!("Bearer minted-for-{subject_key}"),
            )],
            expires_at: i64::MAX,
            cache_binding: format!("{subject_key}@{}", backend.audience),
            subject_key,
            audience: backend.audience.clone(),
            scopes: Vec::new(),
        })
    }
}

type Seen = Arc<parking_lot::Mutex<Vec<(&'static str, String)>>>;

/// One pool slot's transport. Records `(slot, method)` for every message it
/// is handed, notifications included.
struct SlotWire {
    slot: &'static str,
    seen: Seen,
}

#[async_trait::async_trait]
impl crate::transport::Transport for SlotWire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push((self.slot, method.to_string()));
        Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
    }

    async fn notify(&self, method: &str, _params: Option<Value>) -> crate::Result<()> {
        self.seen.lock().push((self.slot, method.to_string()));
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

fn logger(file: &tempfile::NamedTempFile) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: file.path().to_string_lossy().to_string(),
        key_id: "issue-2240".to_string(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("transparency logger opens"))
}

/// A direct-route gateway with one backend, `ledger`, whose shared slot and
/// per-user slots for `alpha` and `beta` record what they are handed.
struct Gateway {
    router: axum::Router,
    auth: Arc<crate::gateway::auth::ResolvedAuthConfig>,
    seen: Seen,
    _store: tempfile::TempDir,
    audit: [tempfile::NamedTempFile; 2],
    /// The route's own transparency log (the one the direct route writes its
    /// mint and refusal rows to), so a cell can fail its next append.
    route_log: Arc<TransparencyLogger>,
}

impl Gateway {
    fn seen(&self) -> Vec<(&'static str, String)> {
        self.seen.lock().clone()
    }

    /// `idp_refuse` rows across the meta and route transparency logs.
    fn refusals(&self) -> usize {
        self.audit
            .iter()
            .map(|file| {
                std::fs::read_to_string(file.path())
                    .unwrap_or_default()
                    .matches("\"idp_refuse\"")
                    .count()
            })
            .sum()
    }
}

fn propagation(strategy: PropagationStrategyKind, required: bool) -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy,
        audience: "ledger".to_string(),
        required,
        session_mode: SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

async fn gateway(config: BackendConfig, multi_user: bool) -> Gateway {
    gateway_with_auth(config, multi_user, crate::config::AuthConfig::default()).await
}

async fn gateway_with_auth(
    config: BackendConfig,
    multi_user: bool,
    auth: crate::config::AuthConfig,
) -> Gateway {
    let seen = Seen::default();
    let backend = Arc::new(Backend::new(
        "ledger",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let wire = |slot| -> Arc<dyn crate::transport::Transport> {
        Arc::new(SlotWire {
            slot,
            seen: Arc::clone(&seen),
        })
    };
    backend.set_transport_for_test(wire("shared"));
    for subject in ["alpha", "beta"] {
        let key = PoolKey::PerUser {
            binding: format!("{subject}@ledger"),
        };
        backend.set_pooled_transport_for_test(&key, wire(subject));
    }

    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let audit = [
        tempfile::NamedTempFile::new().expect("tempfile"),
        tempfile::NamedTempFile::new().expect("tempfile"),
    ];
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(PerIdentityMint));
    meta.enable_transparency_log(logger(&audit[0]));
    meta.set_multi_user(multi_user);
    state_mut.meta_mcp = Arc::new(meta);
    let route_log = logger(&audit[1]);
    state_mut.transparency_log = Some(Arc::clone(&route_log));
    state_mut.auth_config = Arc::new(crate::gateway::auth::ResolvedAuthConfig::from_config(&auth));
    let auth = Arc::clone(&state_mut.auth_config);
    Gateway {
        router: create_router(state),
        auth,
        seen,
        _store: store,
        audit,
        route_log,
    }
}

/// POST the sample notification (`NOTE`) to `/mcp/ledger` as `subject` (verified
/// identity) or anonymously; returns the status and the raw body.
async fn notify(gw: &Gateway, subject: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "method": NOTE, "params": {} }).to_string(),
        ))
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
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

fn refused(status: StatusCode, body: &[u8]) {
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The same `{}` an accepted notification gets: no JSON-RPC response.
    assert_eq!(body, b"{}", "{}", String::from_utf8_lossy(body));
}

fn config_with(identity_propagation: Option<IdentityPropagationConfig>) -> BackendConfig {
    BackendConfig {
        identity_propagation,
        ..BackendConfig::default()
    }
}

/// N2: a `required` minting backend refuses an anonymous notification; no
/// slot sees it and the resolver's refusal is the one audit row.
#[tokio::test]
async fn a_required_backend_refuses_an_anonymous_notification() {
    let gw = gateway(
        config_with(Some(propagation(
            PropagationStrategyKind::SignedAssertion,
            true,
        ))),
        false,
    )
    .await;
    let (status, body) = notify(&gw, None).await;
    refused(status, &body);
    assert_eq!(
        gw.seen(),
        vec![],
        "a slot received the refused notification"
    );
    assert_eq!(gw.refusals(), 1);
}

/// N2b: a `required` passthrough backend with no forwarded credential refuses;
/// the route writes the one audit row (the passthrough arm has no inner one).
#[tokio::test]
async fn a_required_passthrough_backend_refuses_without_a_credential() {
    let gw = gateway(
        config_with(Some(propagation(
            PropagationStrategyKind::Passthrough,
            true,
        ))),
        false,
    )
    .await;
    let (status, body) = notify(&gw, None).await;
    refused(status, &body);
    assert_eq!(gw.seen(), vec![]);
    assert_eq!(gw.refusals(), 1);
}

/// N1: a backend bound to an account with no compiled strategy is refused, as
/// its requests are (`refuse_unbound_account_backend`).
#[tokio::test]
async fn an_unbound_account_backend_refuses_a_notification() {
    let gw = gateway(
        BackendConfig {
            account: Some("ledger-account".to_string()),
            ..BackendConfig::default()
        },
        false,
    )
    .await;
    let (status, body) = notify(&gw, None).await;
    refused(status, &body);
    assert_eq!(gw.seen(), vec![]);
}

/// N5: on a multi-user gateway, a gateway-held OAuth login that is not
/// isolated per user refuses a notification that would ride the shared
/// session, as `enforce_oauth_isolation` refuses its requests.
#[tokio::test]
async fn a_shared_personal_login_refuses_on_a_multi_user_gateway() {
    let oauth = crate::config::OAuthConfig {
        enabled: true,
        scopes: vec![],
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    };
    let gw = gateway(
        BackendConfig {
            oauth: Some(oauth),
            ..BackendConfig::default()
        },
        true,
    )
    .await;
    let (status, body) = notify(&gw, None).await;
    refused(status, &body);
    assert_eq!(gw.seen(), vec![]);
}

/// N4: a verified caller's notification lands on that caller's slot only.
#[tokio::test]
async fn a_verified_callers_notification_lands_on_its_own_slot() {
    let gw = gateway(
        config_with(Some(propagation(
            PropagationStrategyKind::SignedAssertion,
            true,
        ))),
        false,
    )
    .await;
    let (status, _) = notify(&gw, Some("alpha")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(gw.seen(), vec![("alpha", NOTE.to_string())]);
    assert_eq!(gw.refusals(), 0);
}

/// N3 (IDP.5, unchanged): a backend with no personal binding forwards an
/// anonymous notification on the shared session.
#[tokio::test]
async fn a_backend_with_no_personal_binding_still_forwards_on_the_shared_session() {
    for multi_user in [false, true] {
        let gw = gateway(config_with(None), multi_user).await;
        let (status, _) = notify(&gw, None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "multi_user={multi_user}");
        assert_eq!(gw.seen(), vec![("shared", NOTE.to_string())]);
    }
}

/// A non-required propagation backend on a single-user gateway keeps the
/// best-effort shared bucket for an anonymous caller (IDP.5, unchanged).
#[tokio::test]
async fn a_non_required_backend_keeps_the_shared_bucket_for_an_anonymous_caller() {
    let gw = gateway(
        config_with(Some(propagation(
            PropagationStrategyKind::SignedAssertion,
            false,
        ))),
        false,
    )
    .await;
    let (status, _) = notify(&gw, None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(gw.seen(), vec![("shared", NOTE.to_string())]);
}

/// A refused notification is excluded from client accounting: it neither
/// resets the caller's failures (success) nor adds one (failure).
#[tokio::test]
async fn a_refused_notification_leaves_the_client_breaker_untouched() {
    // Auth on, one key, and a client breaker that opens on the second failure.
    let auth = crate::config::AuthConfig {
        enabled: true,
        api_keys: vec![crate::config::ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(b"k-probe")),
            expires_at: None,
            name: "probe".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        client_circuit_breaker: Some(crate::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            ..crate::config::CircuitBreakerConfig::default()
        }),
        ..crate::config::AuthConfig::default()
    };
    let gw = gateway_with_auth(
        config_with(Some(propagation(
            PropagationStrategyKind::SignedAssertion,
            true,
        ))),
        false,
        auth,
    )
    .await;
    gw.auth.record_client_failure("probe"); // 1 of 2
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .header("authorization", "Bearer k-probe")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "method": NOTE, "params": {} }).to_string(),
        ))
        .unwrap();
    let response = gw.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // A refusal that counted a failure would already be open; one that
    // recorded a success would have reset the count, so this one leaves it
    // closed.
    assert_eq!(
        gw.auth.client_circuit_state("probe"),
        Some(crate::failsafe::CircuitState::Closed)
    );
    gw.auth.record_client_failure("probe"); // 2 of 2
    assert_eq!(
        gw.auth.client_circuit_state("probe"),
        Some(crate::failsafe::CircuitState::Open)
    );
}

/// POST `method` (a caller-data request, not a notification) to `/mcp/ledger`
/// anonymously; returns the status and the body.
async fn request(gw: &Gateway, method: &str) -> (StatusCode, Value) {
    request_as(gw, method, None).await
}

/// [`request`] as `subject` (a verified identity) or anonymously.
async fn request_as(gw: &Gateway, method: &str, subject: Option<&str>) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 3, "method": method, "params": {} }).to_string(),
        ))
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
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn shared_login() -> BackendConfig {
    let oauth = crate::config::OAuthConfig {
        enabled: true,
        scopes: vec![],
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    };
    BackendConfig {
        oauth: Some(oauth),
        ..BackendConfig::default()
    }
}

/// ADR-008 INV-2 on the direct route: a request that would ride a shared
/// personal login on a multi-user gateway is refused, as the notification above
/// is. Mutant: telling the guard a per-user credential was resolved when none
/// was lets the request forward on the shared token. The single-user control
/// shows the refusal belongs to the multi-user guard, not the request.
#[tokio::test]
async fn a_shared_personal_login_refuses_a_request_on_a_multi_user_gateway() {
    let single = gateway(shared_login(), false).await;
    let (status, body) = request(&single, "resources/list").await;
    assert_eq!(status, StatusCode::OK, "control: {body}");
    assert_eq!(
        single.seen(),
        vec![("shared", "resources/list".to_string())]
    );

    let multi = gateway(shared_login(), true).await;
    let (status, body) = request(&multi, "resources/list").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.get("error").is_some(), "{body}");
    assert_eq!(multi.seen(), vec![], "the refused request reached a slot");
}

/// A minted credential must never reach the caller without a durable audit
/// record: when the mint row cannot be written the request fails closed and no
/// slot sees it. The control is the same request with a working log.
#[tokio::test]
async fn a_mint_whose_audit_row_cannot_be_written_fails_closed() {
    let required = || {
        config_with(Some(propagation(
            PropagationStrategyKind::SignedAssertion,
            true,
        )))
    };
    let ok = gateway(required(), false).await;
    let (status, body) = request_as(&ok, "resources/list", Some("alpha")).await;
    assert_eq!(status, StatusCode::OK, "control: {body}");

    let gw = gateway(required(), false).await;
    gw.route_log.fail_next_append_for_test();
    let (status, body) = request_as(&gw, "resources/list", Some("alpha")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"]["code"], -32603, "{body}");
    assert_eq!(gw.seen(), vec![], "a slot received the unaudited mint");
}

/// A refusal is audited best-effort: when its row cannot be written the
/// refusal still stands (unlike a mint, it is not failed closed on the audit).
#[tokio::test]
async fn a_refusal_whose_audit_row_cannot_be_written_still_refuses() {
    let gw = gateway(
        config_with(Some(propagation(
            PropagationStrategyKind::Passthrough,
            true,
        ))),
        false,
    )
    .await;
    gw.route_log.fail_next_append_for_test();
    let (status, body) = request_as(&gw, "resources/list", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(gw.seen(), vec![]);
}
