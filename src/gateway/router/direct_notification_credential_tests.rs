// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2292: a direct-route notification carries the caller's resolved
//! credential, as that caller's request would, and never the backend's static
//! one in its place. A credential the transport cannot carry refuses the
//! notification. Forwarding a passthrough credential is audited as a request's
//! is, and never leaks into a trace span.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::direct_route_state_with_identity;
use crate::backend::{Backend, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::test_helpers::MetaMcp;
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

pub(super) const NOTE: &str = "notifications/roots/list_changed";
pub(super) const PASSTHROUGH: &str = "x-mcp-passthrough-authorization";

/// Mints `Bearer minted-for-<subject>` bound to `<subject>@<audience>`, and
/// refuses the subject `mallory`.
struct Mint;

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for Mint {
    async fn propagate(
        &self,
        identity: &VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        if identity.subject == "mallory" {
            return Err(crate::identity_propagation::PropagationError::Refuse(
                "no grant for this principal".to_string(),
            ));
        }
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

/// `(slot, method, authorization)` for every message a slot is handed.
pub(super) type Seen = Arc<parking_lot::Mutex<Vec<(&'static str, String, Option<String>)>>>;

pub(super) struct SlotWire {
    pub(super) slot: &'static str,
    pub(super) seen: Seen,
}

#[async_trait::async_trait]
impl crate::transport::Transport for SlotWire {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.seen.lock().push((self.slot, method.to_string(), None));
        Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> crate::Result<()> {
        self.notify_with_headers(method, params, &[], None).await
    }

    async fn notify_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<()> {
        let auth = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        self.seen.lock().push((self.slot, method.to_string(), auth));
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
        key_id: "issue-2292".to_string(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("transparency logger opens"))
}

struct Gateway {
    router: axum::Router,
    backend: Arc<Backend>,
    seen: Seen,
    _store: tempfile::TempDir,
    audit: [tempfile::NamedTempFile; 2],
}

impl Gateway {
    fn seen(&self) -> Vec<(&'static str, String, Option<String>)> {
        self.seen.lock().clone()
    }

    /// A recording slot for an anonymous passthrough caller whose forwarded
    /// value is `value`: the route keys it by the value's SHA-256 hex digest,
    /// charged to the caller's principal (#2300).
    fn passthrough_slot(&self, value: &str) {
        use sha2::Digest as _;
        let digest = hex::encode(sha2::Sha256::digest(value.as_bytes()));
        let principal = crate::identity_propagation::audit_subject(None);
        let binding = crate::backend::passthrough_binding(&principal, &digest);
        self.backend.set_pooled_transport_for_test(
            &PoolKey::PerUser { binding },
            Arc::new(SlotWire {
                slot: "caller",
                seen: Arc::clone(&self.seen),
            }),
        );
    }

    /// Rows carrying `action` across the meta and route transparency logs.
    fn rows(&self, action: &str) -> usize {
        let needle = format!("\"{action}\"");
        self.audit
            .iter()
            .map(|file| {
                std::fs::read_to_string(file.path())
                    .unwrap_or_default()
                    .matches(needle.as_str())
                    .count()
            })
            .sum()
    }
}

pub(super) fn http() -> TransportConfig {
    TransportConfig::Http {
        http_url: "https://ledger.invalid/mcp".to_string(),
        streamable_http: Some(true),
        protocol_version: None,
    }
}

fn stdio() -> TransportConfig {
    TransportConfig::Stdio {
        command: "ledger-mcp".to_string(),
        cwd: None,
        protocol_version: None,
    }
}

pub(super) fn backend_config(
    transport: TransportConfig,
    strategy: PropagationStrategyKind,
    required: bool,
) -> BackendConfig {
    BackendConfig {
        transport,
        identity_propagation: Some(IdentityPropagationConfig {
            strategy,
            audience: "ledger".to_string(),
            required,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    }
}

/// A single-user direct-route gateway with one backend, `ledger`, whose shared
/// slot and per-user slots for `alpha` and `beta` record what they are handed.
/// `route_log` false leaves the route without a transparency log.
async fn gateway(config: BackendConfig, route_log: bool) -> Gateway {
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
    assert!(
        state_mut.backends.register(Arc::clone(&backend)),
        "fixture registration"
    );
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(Mint));
    meta.enable_transparency_log(logger(&audit[0]));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = route_log.then(|| logger(&audit[1]));
    Gateway {
        router: create_router(state),
        backend,
        seen,
        _store: store,
        audit,
    }
}

/// POST the sample notification (`NOTE`) as `subject` (verified identity) or
/// anonymously, with an optional passthrough credential.
async fn notify(gw: &Gateway, subject: Option<&str>, passthrough: Option<&str>) -> StatusCode {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/ledger")
        .header("content-type", "application/json");
    if let Some(value) = passthrough {
        builder = builder.header(PASSTHROUGH, value);
    }
    let mut request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "method": NOTE, "params": { "requestId": 7 } }).to_string(),
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
    let _ = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    status
}

fn auth(slot: &'static str, value: &str) -> (&'static str, String, Option<String>) {
    (slot, NOTE.to_string(), Some(value.to_string()))
}

/// W1, the issue's fail-fast: a required-passthrough notification reaches the
/// upstream with the caller's own value, never without it (where the static
/// credential would go). One `idp_mint` row records it, as for a request.
#[tokio::test]
async fn a_passthrough_notification_carries_the_callers_credential() {
    let gw = gateway(
        backend_config(http(), PropagationStrategyKind::Passthrough, true),
        true,
    )
    .await;
    let value = format!("Bearer {}", "caller-own");
    gw.passthrough_slot(&value);
    assert_eq!(notify(&gw, None, Some(&value)).await, StatusCode::ACCEPTED);
    assert_eq!(gw.seen(), vec![auth("caller", &value)]);
    assert_eq!(gw.rows("idp_mint"), 1);
}

/// W2: a minting backend's notification carries each caller's minted
/// credential on that caller's slot.
#[tokio::test]
async fn a_minted_notification_carries_each_callers_credential() {
    let gw = gateway(
        backend_config(http(), PropagationStrategyKind::SignedAssertion, true),
        true,
    )
    .await;
    for subject in ["alpha", "beta"] {
        assert_eq!(notify(&gw, Some(subject), None).await, StatusCode::ACCEPTED);
    }
    assert_eq!(
        gw.seen(),
        vec![
            auth("alpha", "Bearer minted-for-alpha"),
            auth("beta", "Bearer minted-for-beta"),
        ]
    );
}

/// W3: a non-required minting backend on a transport that cannot carry the
/// minted credential refuses the notification rather than send it with the
/// static one. The refusal is audited, and decided before minting, so the log
/// shows no mint for a notification that never left (#2310).
#[tokio::test]
async fn a_credential_the_transport_cannot_carry_refuses_the_notification() {
    let gw = gateway(
        backend_config(stdio(), PropagationStrategyKind::SignedAssertion, false),
        true,
    )
    .await;
    assert_eq!(
        notify(&gw, Some("alpha"), None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(gw.seen(), vec![]);
    assert_eq!(gw.rows("idp_refuse"), 1);
    assert_eq!(gw.rows("idp_mint"), 0);
}

/// #2310: a non-required passthrough credential the transport cannot carry
/// refuses the notification with one `idp_refuse` row.
#[tokio::test]
async fn an_uncarried_passthrough_refusal_is_audited() {
    let gw = gateway(
        backend_config(stdio(), PropagationStrategyKind::Passthrough, false),
        true,
    )
    .await;
    let value = format!("Bearer {}", "caller-own");
    gw.passthrough_slot(&value);
    assert_eq!(notify(&gw, None, Some(&value)).await, StatusCode::FORBIDDEN);
    assert_eq!(gw.seen(), vec![]);
    assert_eq!(gw.rows("idp_refuse"), 1);
    assert_eq!(gw.rows("idp_mint"), 0);
}

/// #2310: on a required backend that cannot carry the credential, a caller
/// with a principal is refused by the route and an anonymous one by the
/// resolver; either way exactly one `idp_refuse` row, no `idp_mint`.
#[tokio::test]
async fn a_required_uncarried_refusal_is_audited_once_per_caller() {
    for subject in [Some("alpha"), None] {
        let gw = gateway(
            backend_config(stdio(), PropagationStrategyKind::SignedAssertion, true),
            true,
        )
        .await;
        assert_eq!(notify(&gw, subject, None).await, StatusCode::FORBIDDEN);
        assert_eq!(gw.seen(), vec![]);
        assert_eq!(gw.rows("idp_refuse"), 1, "{subject:?}");
        assert_eq!(gw.rows("idp_mint"), 0, "{subject:?}");
    }
}

/// #2310 guard: a caller with no principal mints nothing on a non-required
/// backend, so its notification keeps the shared, static path (IDP.5) even on
/// a transport that could not carry a credential.
#[tokio::test]
async fn an_anonymous_notification_keeps_the_static_path() {
    let gw = gateway(
        backend_config(stdio(), PropagationStrategyKind::SignedAssertion, false),
        true,
    )
    .await;
    assert_eq!(notify(&gw, None, None).await, StatusCode::ACCEPTED);
    assert_eq!(gw.seen(), vec![("shared", NOTE.to_string(), None)]);
    assert_eq!(gw.rows("idp_refuse") + gw.rows("idp_mint"), 0);
}

/// W4 (moved from #2240): a verified caller whose credential the resolver
/// refuses gets 403 on a required backend, and no slot sees the notification.
#[tokio::test]
async fn a_refused_principal_is_refused_for_a_notification() {
    let gw = gateway(
        backend_config(http(), PropagationStrategyKind::SignedAssertion, true),
        true,
    )
    .await;
    assert_eq!(
        notify(&gw, Some("mallory"), None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(gw.seen(), vec![]);
}

/// W5 (moved from #2240): an unbound-account notification refusal writes
/// exactly one `idp_refuse` row, as the request arm does.
#[tokio::test]
async fn an_unbound_account_refusal_is_audited_once() {
    let gw = gateway(
        BackendConfig {
            transport: http(),
            account: Some("ledger-account".to_string()),
            ..BackendConfig::default()
        },
        true,
    )
    .await;
    assert_eq!(notify(&gw, None, None).await, StatusCode::FORBIDDEN);
    assert_eq!(gw.seen(), vec![]);
    assert_eq!(gw.rows("idp_refuse"), 1);
}

/// W6: a required passthrough credential is not forwarded when the route has
/// no durable audit record to write, as a request is not.
#[tokio::test]
async fn a_required_passthrough_notification_needs_the_audit_log() {
    let gw = gateway(
        backend_config(http(), PropagationStrategyKind::Passthrough, true),
        false,
    )
    .await;
    let value = format!("Bearer {}", "caller-own");
    gw.passthrough_slot(&value);
    assert_ne!(notify(&gw, None, Some(&value)).await, StatusCode::ACCEPTED);
    assert_eq!(gw.seen(), vec![]);
}

/// Guard: the forwarded credential never reaches a trace span.
#[tokio::test]
async fn a_forwarded_credential_stays_out_of_the_trace() {
    use std::io::Write;
    #[derive(Clone)]
    struct Buf(Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = Buf(Arc::default());
    let writer = buffer.clone();
    crate::gateway::session_id::log_capture::ensure_global_interest();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let gw = gateway(
        backend_config(http(), PropagationStrategyKind::Passthrough, true),
        true,
    )
    .await;
    let secret = format!("Bearer {}", "never-in-a-span");
    gw.passthrough_slot(&secret);
    assert_eq!(notify(&gw, None, Some(&secret)).await, StatusCode::ACCEPTED);
    let trace = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(
        trace.contains("notify_with_headers"),
        "the span was captured"
    );
    assert!(!trace.contains("never-in-a-span"), "{trace}");
}
